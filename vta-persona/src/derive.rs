//! Deriving a credential-backed value from its credential, and failing closed.
//!
//! A `credentialBacked` attribute's stored value is **a cache for display; the
//! credential is the truth** (`persona-record` Provenance). The specification
//! requires the maintainer to resolve the credential and its `claimPath` when
//! the attribute is written (`persona/attribute/put` rule 3,
//! `credentialNotFound`), and to re-derive the value on every read, failing
//! closed — never presenting a stale value — once the credential has been
//! revoked, has expired, or has been archived or deleted.
//!
//! # A hook, not a dependency
//!
//! This crate does not read the vault. The service does, and hands the store a
//! [`CredentialSource`] that answers one question: what does this credential
//! say at this path, *now*, or why can it not be relied on. A store with no
//! source — a unit test, an offline tool — serves the cached value as before;
//! the service always installs one.
//!
//! # Where it is asked
//!
//! Everywhere a credential-backed value is about to be believed: resolving a
//! face (which is also what materialising a binding does), listing the pool,
//! building a disclosure preview, and presenting one. The last matters on its
//! own: a credential revoked between a preview and its presentation must not
//! be presented.

use std::sync::Arc;

use vti_common::error::AppError;

use crate::model::{Provenance, StaleReason};

/// What a credential says at a path, or why it cannot be relied on.
#[derive(Clone, Debug, PartialEq)]
pub enum Derived {
    /// The value at the path, from a credential that is current.
    Value(serde_json::Value),
    /// The credential cannot back a value now, and why.
    Stale(StaleReason),
}

/// The vault, as the persona store needs it.
#[async_trait::async_trait]
pub trait CredentialSource: Send + Sync {
    /// The value `credential_id` carries at `claim_path` (RFC 6901), or why it
    /// cannot be relied on. An `Err` is a failure to ask — a store error — and
    /// is distinct from a credential that answered "stale".
    async fn derive(&self, credential_id: &str, claim_path: &str) -> Result<Derived, AppError>;
}

/// A shareable source.
pub type SharedCredentialSource = Arc<dyn CredentialSource>;

impl crate::PersonaStore {
    /// Install the source the store derives credential-backed values from.
    #[must_use]
    pub fn with_credentials(mut self, source: SharedCredentialSource) -> Self {
        self.credentials = Some(source);
        self
    }

    /// Re-derive a value under `provenance`.
    ///
    /// `None` when there is nothing to derive — the provenance is not
    /// credential-backed, or no source is installed — and the cached value
    /// stands. Otherwise the credential's answer.
    pub(crate) async fn rederive(
        &self,
        provenance: &Provenance,
    ) -> Result<Option<Derived>, AppError> {
        let (
            Some(source),
            Provenance::CredentialBacked {
                credential_id,
                claim_path,
                ..
            },
        ) = (self.credentials.as_ref(), provenance)
        else {
            return Ok(None);
        };
        source.derive(credential_id, claim_path).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProfileEntry, ValueType};
    use crate::profile::new_profile;
    use crate::store::new_attribute;
    use serde_json::json;
    use std::sync::Mutex;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A vault whose answer the test changes: current, or withdrawn.
    struct Vault(Mutex<Derived>);

    #[async_trait::async_trait]
    impl CredentialSource for Vault {
        async fn derive(&self, credential_id: &str, claim_path: &str) -> Result<Derived, AppError> {
            assert_eq!(credential_id, "cred-1");
            assert_eq!(claim_path, "/credentialSubject/name");
            Ok(self.0.lock().unwrap().clone())
        }
    }

    async fn fresh(vault: Arc<Vault>) -> (tempfile::TempDir, crate::PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        (
            dir,
            crate::PersonaStore::new(ks, [41u8; 32]).with_credentials(vault),
        )
    }

    fn backed(value: &str) -> crate::Attribute {
        new_attribute(
            "name.legal",
            ValueType::String,
            json!(value),
            Provenance::CredentialBacked {
                credential_id: "cred-1".into(),
                claim_path: "/credentialSubject/name".into(),
                issuer_did: None,
                proof: None,
            },
        )
    }

    fn set(vault: &Vault, d: Derived) {
        *vault.0.lock().unwrap() = d;
    }

    /// Written with the credential's value, not the one supplied; refused when
    /// the credential cannot back it.
    #[tokio::test]
    async fn a_write_takes_the_credentials_value_and_refuses_a_withdrawn_one() {
        let vault = Arc::new(Vault(Mutex::new(Derived::Value(json!("Ada Lovelace")))));
        let (_d, s) = fresh(vault.clone()).await;
        let a = backed("typed by hand");
        s.put(a.clone(), None).await.unwrap();
        assert_eq!(
            s.get(&a.attribute_id).await.unwrap().unwrap().value,
            Some(json!("Ada Lovelace"))
        );

        set(&vault, Derived::Stale(StaleReason::NotFound));
        assert_eq!(
            s.credential_refusal(&backed("x").provenance).await.unwrap(),
            Some(StaleReason::NotFound)
        );
        assert!(s.put(backed("x"), None).await.is_err());
    }

    /// A face stops showing a value the moment its credential is revoked — the
    /// listing says why, the face shows nothing for it, and a disclosure
    /// previewed before the revocation is not presented after it.
    #[tokio::test]
    async fn a_revoked_credential_stops_backing_its_value_everywhere() {
        let vault = Arc::new(Vault(Mutex::new(Derived::Value(json!("Ada Lovelace")))));
        let (_d, s) = fresh(vault.clone()).await;
        let a = backed("Ada Lovelace");
        s.put(a.clone(), None).await.unwrap();
        let face = new_profile(
            "Bank",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
                slot: None,
            }],
        );
        let face_id = face.profile_id.clone();
        s.put_profile(face, None).await.unwrap();
        s.set_binding(
            "bank",
            "did:key:zP",
            Some(&face_id),
            vec![],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let preview = s
            .create_preview("bank", "did:key:zP", "did:web:bank", None, None, None)
            .await
            .unwrap();
        assert!(!preview.claims[0].stale);

        set(&vault, Derived::Stale(StaleReason::Revoked));

        let listed = s
            .list_attributes(None, crate::ValueVisibility::All)
            .await
            .unwrap()
            .attributes;
        assert_eq!(listed[0].stale, Some(true));
        assert_eq!(listed[0].stale_reason, Some(StaleReason::Revoked));
        assert_eq!(
            listed[0].value, None,
            "a withdrawn credential's value is not shown"
        );

        let resolved = s.resolve_profile(&face_id).await.unwrap();
        assert!(resolved[0].stale);
        assert_eq!(resolved[0].value, None);

        assert!(
            matches!(
                s.present(&preview.preview_id, None, false).await,
                Err(AppError::Conflict(_))
            ),
            "a preview is not a licence to present a credential revoked since"
        );

        let again = s
            .create_preview("bank", "did:key:zP", "did:web:bank", None, None, None)
            .await
            .unwrap();
        assert!(
            again.claims[0].stale,
            "a new preview shows it stale before anything is approved"
        );
    }
}
