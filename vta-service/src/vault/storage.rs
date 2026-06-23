//! Primary persistence for the credential vault (task 1.1).
//!
//! Stores [`StoredCredential`] records under the `cred:<id>` key namespace
//! in the `vault` keyspace and keeps the secondary index ([`super::index`])
//! in lock-step on every mutation. The whole record value — including the
//! opaque credential body — is encrypted at rest by the keyspace's
//! AES-256-GCM wrapper when the deployment supplies a storage key.
//!
//! This layer is format-agnostic and does **no** cryptographic work: it
//! does not verify issuer signatures, check status lists, or disclose
//! claims. Those are later tasks. It also exposes **no enumeration
//! primitive** — there is no `list_all`; discovery is index-scan-only
//! (`vti-credential-architecture.md` §14).

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::index;
use super::model::{IndexField, StoredCredential};

/// Primary-key prefix for credential records. Disjoint from `idx:` (the
/// secondary index) and `vault:` (the password-manager `VaultEntry` records
/// that share this keyspace).
const RECORD_PREFIX: &str = "cred:";

/// `cred:<id>` — the primary key for one stored credential.
fn record_key(id: &str) -> Vec<u8> {
    format!("{RECORD_PREFIX}{id}").into_bytes()
}

/// Store (create or overwrite) a credential and (re)build its index entries.
///
/// On overwrite, the *previous* record's index terms are removed first so a
/// changed `status` / `community_did` / etc. never leaves a stale index row
/// pointing at this id under its old value. The record value is encrypted
/// at rest; the index keys carry only routing metadata, never the body.
///
/// The credential `id` must be non-empty (it is the primary key); an empty
/// id is rejected rather than silently writing to `cred:`.
pub async fn put(vault: &KeyspaceHandle, cred: &StoredCredential) -> Result<(), AppError> {
    if cred.id.trim().is_empty() {
        return Err(AppError::Validation(
            "StoredCredential.id must be non-empty".to_string(),
        ));
    }

    // Remove the prior record's index terms before re-indexing, so an
    // update that changes an indexed field doesn't orphan the old row.
    if let Some(prev) = get(vault, &cred.id).await? {
        index::remove_for(vault, &prev).await?;
    }

    vault.insert(record_key(&cred.id), cred).await?;
    index::insert_for(vault, cred).await?;
    Ok(())
}

/// Fetch a credential by its local id. Returns `Ok(None)` for an absent id
/// so callers map to their own not-found / permission-denied policy. The
/// returned record includes the decrypted opaque body — callers that only
/// need metadata should still treat the body as opaque.
pub async fn get(vault: &KeyspaceHandle, id: &str) -> Result<Option<StoredCredential>, AppError> {
    vault.get(record_key(id)).await
}

/// Delete a credential by id and tear down all of its index entries.
/// Idempotent: deleting an absent id is a no-op (returns `Ok`).
pub async fn delete(vault: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    if let Some(prev) = get(vault, id).await? {
        index::remove_for(vault, &prev).await?;
    }
    vault.remove(record_key(id)).await?;
    Ok(())
}

/// Resolve every credential indexed under `(field, value)` to its full
/// record. This is the targeted search primitive: it requires an explicit
/// field **and** value, scans the index for matching ids, then loads only
/// those records. There is intentionally no variant that returns every
/// credential — see `vti-credential-architecture.md` §14.
///
/// An index row whose primary record has since vanished (a torn write, or a
/// race) is skipped rather than erroring, so a stale index entry can never
/// wedge a search.
pub async fn find_by_index(
    vault: &KeyspaceHandle,
    field: IndexField,
    value: &str,
) -> Result<Vec<StoredCredential>, AppError> {
    let ids = index::scan(vault, field, value).await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(rec) = get(vault, &id).await? {
            out.push(rec);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{CredentialFormat, CredentialPurpose, CredentialStatus};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A fresh tempdir-backed store plus a `vault` keyspace handle. The
    /// `TempDir` and `Store` are returned so the caller keeps the fjall
    /// files (and DB handle) alive for the duration of the test. When `key`
    /// is `Some`, the returned handle is wrapped in the AES-256-GCM at-rest
    /// layer; the underlying store is unchanged, so a second *plain* handle
    /// can be opened on the same keyspace to read the on-disk ciphertext.
    fn fresh_vault(key: Option<[u8; 32]>) -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace(crate::keyspaces::VAULT)
            .expect("vault keyspace");
        let ks = match key {
            Some(k) => ks.with_encryption(k),
            None => ks,
        };
        (dir, store, ks)
    }

    fn sample(id: &str) -> StoredCredential {
        StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::SdJwtVc,
            types: vec!["VerifiableCredential".into(), "InvitationCredential".into()],
            schema_id: Some("schema:invite:1".into()),
            community_did: Some("did:web:acme".into()),
            context_id: None,
            subject_did: Some("did:key:zAlice".into()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: Some(CredentialPurpose::Invite),
            status: CredentialStatus::Unknown,
            valid_from: Some("2026-01-01T00:00:00Z".into()),
            valid_until: Some("2027-01-01T00:00:00Z".into()),
            received_at: "2026-06-03T00:00:00Z".into(),
            source: Some("exchange:thread-42".into()),
            tags: std::collections::BTreeMap::from([("label".into(), "alice-invite".into())]),
            body: b"opaque.credential.bytes".to_vec(),
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        }
    }

    #[tokio::test]
    async fn store_then_get_by_id_round_trips() {
        let (_dir, _store, vault) = fresh_vault(None);
        let cred = sample("cred-1");
        put(&vault, &cred).await.unwrap();

        let got = get(&vault, "cred-1").await.unwrap().expect("present");
        assert_eq!(got, cred, "full record round-trips byte-for-byte");

        // Absent id → None, never an error (caller maps to not-found).
        assert!(get(&vault, "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn prefix_scan_index_hits_each_indexed_field() {
        let (_dir, _store, vault) = fresh_vault(None);
        put(&vault, &sample("cred-1")).await.unwrap();

        // type (both tags reachable)
        let by_type = find_by_index(&vault, IndexField::Type, "InvitationCredential")
            .await
            .unwrap();
        assert_eq!(by_type.len(), 1);
        assert_eq!(by_type[0].id, "cred-1");
        assert_eq!(
            find_by_index(&vault, IndexField::Type, "VerifiableCredential")
                .await
                .unwrap()
                .len(),
            1
        );

        // community_did
        assert_eq!(
            find_by_index(&vault, IndexField::CommunityDid, "did:web:acme")
                .await
                .unwrap()
                .len(),
            1
        );
        // issuer_did
        assert_eq!(
            find_by_index(&vault, IndexField::IssuerDid, "did:web:issuer.example")
                .await
                .unwrap()
                .len(),
            1
        );
        // purpose
        assert_eq!(
            find_by_index(&vault, IndexField::Purpose, "invite")
                .await
                .unwrap()
                .len(),
            1
        );
        // status (defaults to unknown at store time)
        assert_eq!(
            find_by_index(&vault, IndexField::Status, "unknown")
                .await
                .unwrap()
                .len(),
            1
        );

        // A value that matches nothing returns empty, never an error.
        assert!(
            find_by_index(&vault, IndexField::IssuerDid, "did:web:other")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn index_scans_isolate_distinct_credentials() {
        let (_dir, _store, vault) = fresh_vault(None);

        let mut a = sample("cred-a");
        a.issuer_did = Some("did:web:issuer-a".into());
        a.community_did = Some("did:web:acme".into());

        let mut b = sample("cred-b");
        b.issuer_did = Some("did:web:issuer-b".into());
        b.community_did = Some("did:web:acme".into());

        put(&vault, &a).await.unwrap();
        put(&vault, &b).await.unwrap();

        // Shared community → both.
        let mut shared = find_by_index(&vault, IndexField::CommunityDid, "did:web:acme")
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.id)
            .collect::<Vec<_>>();
        shared.sort();
        assert_eq!(shared, vec!["cred-a", "cred-b"]);

        // Distinct issuer → exactly one each.
        let only_a = find_by_index(&vault, IndexField::IssuerDid, "did:web:issuer-a")
            .await
            .unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].id, "cred-a");
    }

    #[tokio::test]
    async fn update_reindexes_and_drops_stale_rows() {
        let (_dir, _store, vault) = fresh_vault(None);
        let mut cred = sample("cred-1");
        put(&vault, &cred).await.unwrap();

        // Initially indexed under status=unknown.
        assert_eq!(
            find_by_index(&vault, IndexField::Status, "unknown")
                .await
                .unwrap()
                .len(),
            1
        );

        // Flip status → revoked and re-store.
        cred.status = CredentialStatus::Revoked;
        put(&vault, &cred).await.unwrap();

        // Old status row is gone; new one is present. No double-counting.
        assert!(
            find_by_index(&vault, IndexField::Status, "unknown")
                .await
                .unwrap()
                .is_empty(),
            "stale status=unknown index row must be removed on update"
        );
        assert_eq!(
            find_by_index(&vault, IndexField::Status, "revoked")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn delete_removes_record_and_all_index_rows() {
        let (_dir, _store, vault) = fresh_vault(None);
        put(&vault, &sample("cred-1")).await.unwrap();

        delete(&vault, "cred-1").await.unwrap();

        assert!(get(&vault, "cred-1").await.unwrap().is_none());
        for (field, value) in [
            (IndexField::Type, "InvitationCredential"),
            (IndexField::CommunityDid, "did:web:acme"),
            (IndexField::IssuerDid, "did:web:issuer.example"),
            (IndexField::Purpose, "invite"),
            (IndexField::Status, "unknown"),
        ] {
            assert!(
                find_by_index(&vault, field, value)
                    .await
                    .unwrap()
                    .is_empty(),
                "index row for {field:?}={value} must be gone after delete"
            );
        }

        // Deleting an absent id is a no-op.
        delete(&vault, "cred-1").await.unwrap();
    }

    #[tokio::test]
    async fn empty_id_is_rejected() {
        let (_dir, _store, vault) = fresh_vault(None);
        let cred = sample("");
        let err = put(&vault, &cred).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn body_is_encrypted_at_rest() {
        // With an at-rest key, the opaque body must not appear in cleartext
        // anywhere in the keyspace's stored value bytes. Scanning the raw
        // (still-encrypted) record value proves the AES-GCM wrapper engaged.
        let key = [7u8; 32];
        let (_dir, store, vault) = fresh_vault(Some(key));
        assert!(vault.is_encrypted());

        let cred = sample("cred-secret");
        put(&vault, &cred).await.unwrap();

        // Read the SAME keyspace through a second handle that has NO
        // encryption key. `get_raw` only decrypts when its handle carries a
        // key, so this plain handle returns the actual on-disk ciphertext —
        // the genuine "at rest" bytes, not a decrypted view.
        let plain = store
            .keyspace(crate::keyspaces::VAULT)
            .expect("plain vault handle");
        assert!(!plain.is_encrypted());
        let raw = plain
            .get_raw(record_key("cred-secret"))
            .await
            .unwrap()
            .expect("raw record present");
        // Neither the opaque body nor any plaintext metadata (the id, the
        // issuer DID) may appear in the ciphertext.
        assert!(
            !contains_subslice(&raw, b"opaque.credential.bytes"),
            "credential body must be ciphertext at rest, found cleartext"
        );
        assert!(
            !contains_subslice(&raw, b"cred-secret"),
            "record metadata must be ciphertext at rest, found cleartext id"
        );
        assert!(
            !contains_subslice(&raw, b"did:web:issuer.example"),
            "record metadata must be ciphertext at rest, found cleartext issuer DID"
        );

        // Through the decrypting handle the body round-trips intact.
        let got = get(&vault, "cred-secret").await.unwrap().expect("present");
        assert_eq!(got.body, b"opaque.credential.bytes".to_vec());

        // And searches still work over the encrypted store (index keys are
        // plaintext metadata; only the value is encrypted).
        assert_eq!(
            find_by_index(&vault, IndexField::Purpose, "invite")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
