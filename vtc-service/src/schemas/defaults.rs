//! Default **Issues** registrations seeded at community boot (task 2.x
//! follow-up). The VTC always mints its built-in catalog types; seeding them
//! into the schema store means the registry accurately reflects what the
//! community issues, so issue-time validation ([`super::validate_issued`]) and
//! the admin UI have entries to work with out of the box.
//!
//! Seeding is **idempotent** and additive: it registers a default
//! [`SchemaEntry`] (kind [`Issues`](super::SchemaKind::Issues), no
//! `credentialSchema`) for any catalog type not already present, and never
//! overwrites an operator's edits.

use chrono::Utc;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{SchemaEntry, SchemaKind, schema_exists, store_schema};

/// The built-in catalog types the VTC issues, keyed by the short type name the
/// DTG catalog stamps in a credential's `type` array (what
/// [`super::validate_issued`] matches against). `(type_uri, dtg_type)`.
pub const DEFAULT_ISSUES_TYPES: &[(&str, &str)] = &[
    ("MembershipCredential", "MembershipCredential"),
    ("EndorsementCredential", "EndorsementCredential"),
    ("InvitationCredential", "InvitationCredential"),
];

/// The DID recorded as the registrant of a seeded default.
const SEED_AUTHOR: &str = "did:vtc:system";

/// Seed the default Issues registrations for the catalog types the VTC mints,
/// for any not already registered. Idempotent — safe to call on every boot.
pub async fn seed_default_issues(schemas_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let now = Utc::now();
    for (type_uri, dtg_type) in DEFAULT_ISSUES_TYPES {
        if schema_exists(schemas_ks, type_uri).await? {
            continue;
        }
        store_schema(
            schemas_ks,
            &SchemaEntry {
                type_uri: (*type_uri).to_string(),
                dtg_type: Some((*dtg_type).to_string()),
                credential_schema: None,
                kind: SchemaKind::Issues,
                description: Some("Built-in catalog type (seeded default)".to_string()),
                created_at: now,
                created_by_did: SEED_AUTHOR.to_string(),
            },
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{SchemaEntry, SchemaKind, get_schema, is_issues_registered, store_schema};
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("schemas").unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn seeds_the_catalog_issues_types() {
        let (_d, _s, ks) = ks().await;
        seed_default_issues(&ks).await.unwrap();

        for (type_uri, _) in DEFAULT_ISSUES_TYPES {
            assert!(
                is_issues_registered(&ks, type_uri).await.unwrap(),
                "{type_uri} must be seeded as an Issues type"
            );
        }
    }

    #[tokio::test]
    async fn is_idempotent_and_preserves_operator_edits() {
        let (_d, _s, ks) = ks().await;

        // An operator pre-registers Membership with a custom schema.
        let custom = SchemaEntry {
            type_uri: "MembershipCredential".into(),
            dtg_type: Some("MembershipCredential".into()),
            credential_schema: Some(serde_json::json!({ "type": "object" })),
            kind: SchemaKind::Issues,
            description: Some("operator-tuned".into()),
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        };
        store_schema(&ks, &custom).await.unwrap();

        // Seeding twice must not clobber the operator's entry.
        seed_default_issues(&ks).await.unwrap();
        seed_default_issues(&ks).await.unwrap();

        let got = get_schema(&ks, "MembershipCredential")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, custom, "seeding must not overwrite an existing entry");
        // The other defaults are still seeded.
        assert!(
            is_issues_registered(&ks, "InvitationCredential")
                .await
                .unwrap()
        );
    }
}
