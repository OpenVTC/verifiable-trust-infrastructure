//! Issue-time JSON-Schema validation (task 2.3,
//! `docs/05-design-notes/vti-credential-architecture.md` §8).
//!
//! When the VTC mints a credential whose type is registered in the
//! [schema store](super) with a `credentialSchema`, the credential's
//! `credentialSubject` is validated against that JSON Schema **before** the
//! credential leaves the issuer. A non-conforming credential is refused
//! ([`AppError::Validation`]).
//!
//! Validation is **opt-in by registration**: a credential whose type isn't
//! registered, or whose registered entry carries no schema, passes unchecked
//! (the separate "only registered types may be issued" gate is a follow-up).

use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::get_schema;

/// Validate a JSON `instance` against a JSON Schema `schema`.
///
/// Returns [`AppError::Validation`] on the first schema violation, or
/// [`AppError::Internal`] if the schema document itself is not a valid JSON
/// Schema.
pub fn validate_instance(schema: &Value, instance: &Value) -> Result<(), AppError> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|e| AppError::Internal(format!("invalid credentialSchema: {e}")))?;
    if let Err(error) = validator.validate(instance) {
        return Err(AppError::Validation(format!(
            "credential does not conform to its registered schema: {error}"
        )));
    }
    Ok(())
}

/// The credential's candidate type names (its `type` array minus the universal
/// `VerifiableCredential`), in order — these are matched against schema-store
/// `type_uri`s.
fn candidate_types(credential: &Value) -> Vec<String> {
    credential
        .get("type")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|t| *t != "VerifiableCredential")
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Validate a just-issued credential against the JSON Schema registered for its
/// type, if any. The credential's `credentialSubject` is the validated instance.
///
/// No-op (`Ok`) when no candidate type is registered, or the registered entry
/// has no `credentialSchema`.
pub async fn validate_issued(
    schemas_ks: &KeyspaceHandle,
    credential: &Value,
) -> Result<(), AppError> {
    for type_uri in candidate_types(credential) {
        let Some(entry) = get_schema(schemas_ks, &type_uri).await? else {
            continue;
        };
        // Registered: enforce its schema if it has one, else accept.
        return match &entry.credential_schema {
            Some(schema) => {
                let subject = credential.get("credentialSubject").unwrap_or(&Value::Null);
                validate_instance(schema, subject)
            }
            None => Ok(()),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{SchemaEntry, SchemaKind, store_schema};
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn membership_credential() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:acme",
            "credentialSubject": { "id": "did:key:zMember", "tier": "gold" }
        })
    }

    #[test]
    fn validate_instance_accepts_and_rejects() {
        let schema = json!({
            "type": "object",
            "properties": { "id": { "type": "string" }, "tier": { "enum": ["gold", "silver"] } },
            "required": ["id", "tier"]
        });
        // Conforming.
        validate_instance(&schema, &json!({ "id": "x", "tier": "gold" })).expect("conforms");
        // Missing required field.
        assert!(matches!(
            validate_instance(&schema, &json!({ "id": "x" })),
            Err(AppError::Validation(_))
        ));
        // Out-of-enum value.
        assert!(matches!(
            validate_instance(&schema, &json!({ "id": "x", "tier": "bronze" })),
            Err(AppError::Validation(_))
        ));
    }

    async fn ks_with(schema: Option<Value>) -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("schemas").unwrap();
        let entry = SchemaEntry {
            type_uri: "MembershipCredential".into(),
            dtg_type: Some("MembershipCredential".into()),
            credential_schema: schema,
            kind: SchemaKind::Issues,
            description: None,
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        };
        store_schema(&ks, &entry).await.unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn validate_issued_enforces_a_registered_schema() {
        // Schema requires `tier` — the credential has it → passes.
        let (_d, _s, ks) = ks_with(Some(json!({
            "type": "object",
            "required": ["id", "tier"]
        })))
        .await;
        validate_issued(&ks, &membership_credential())
            .await
            .expect("conforming credential passes");

        // Schema requires a field the credential lacks → rejected at issue.
        let (_d2, _s2, ks2) = ks_with(Some(json!({
            "type": "object",
            "required": ["id", "endorsedBy"]
        })))
        .await;
        assert!(matches!(
            validate_issued(&ks2, &membership_credential()).await,
            Err(AppError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn validate_issued_is_a_noop_for_unregistered_or_schemaless() {
        // Registered but no credentialSchema → accept.
        let (_d, _s, ks) = ks_with(None).await;
        validate_issued(&ks, &membership_credential())
            .await
            .expect("schemaless registration accepts");

        // Unregistered type → accept (no gate here).
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let empty = store.keyspace("schemas").unwrap();
        validate_issued(&empty, &membership_credential())
            .await
            .expect("unregistered type accepts");
    }
}
