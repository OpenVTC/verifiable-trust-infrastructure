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
    let validator = jsonschema::validator_for(schema).map_err(|e| {
        AppError::Internal(format!("invalid credentialSchema: {}", describe_bad(&e)))
    })?;
    if let Err(error) = validator.validate(instance) {
        return Err(AppError::Validation(format!(
            "credential does not conform to its registered schema: {error}"
        )));
    }
    Ok(())
}

/// Refuse a document that is not itself a valid JSON Schema, naming the part
/// that is wrong.
///
/// The compile is the **same** call [`validate_instance`] makes, deliberately:
/// a schema this accepts is one validation can use, and a schema this refuses
/// is one validation would choke on. That correspondence is the whole point of
/// checking at registration — #1649 made `vtc/endorsements/issue/0.1` enforce
/// an endorsement type's stored `claimSchema` and nothing had ever checked that
/// the stored document *was* a schema, so a type registered with a malformed
/// one answered every later issuance with an opaque 500. A separate, stricter
/// gate here would only move that failure to a different pair of inputs.
///
/// A non-object is refused before the compile: `claimSchema` is `"type":
/// "object"` in `vtc/endorsement-types/register/0.1`'s payload schema, while
/// JSON Schema itself accepts the bare booleans `true` and `false` as schemas —
/// so the compile alone would let `true` through.
///
/// The `Err` is the operator-facing detail, prefixed with the JSON Pointer into
/// the schema when the error carries one (`at /properties/level/type: …`), so
/// the answer names the bad keyword rather than the whole document.
pub fn check_schema(schema: &Value) -> Result<(), String> {
    if !schema.is_object() {
        return Err(format!(
            "expected a JSON object, found {}",
            json_type_name(schema)
        ));
    }
    jsonschema::validator_for(schema)
        .map(|_| ())
        .map_err(|e| describe_bad(&e))
}

/// A compile failure as an operator reads it: the location inside the schema
/// document, then what is wrong there.
fn describe_bad(e: &jsonschema::ValidationError<'_>) -> String {
    let at = e.instance_path().to_string();
    if at.is_empty() || at == "/" {
        e.to_string()
    } else {
        format!("at {at}: {e}")
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
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
mod external_ref_tests {
    use super::validate_instance;
    use serde_json::json;

    /// A caller-supplied schema must not be able to make the VTC fetch a URL
    /// or read a local file while it is compiled (#1657 follow-up).
    ///
    /// Every schema reaching `jsonschema` here is supplied by a caller — a
    /// `credentialSchema` at registration, an endorsement type's
    /// `claimSchema`, and both again at issuance. The crate enables
    /// `resolve-http` and `resolve-file` by default, which turns an external
    /// `$ref` into an outbound request or a file read. The workspace manifest
    /// turns both off; this holds that manifest honest, since nothing else
    /// would notice if the features came back.
    ///
    /// The `file:` case is the decisive one: the target really exists and
    /// really is a valid schema, so it would compile if the resolver were on.
    #[test]
    fn an_external_ref_is_refused_rather_than_fetched() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("ref-target.json");
        std::fs::write(&target, br#"{"type": "string"}"#).expect("write target");
        assert!(target.exists());

        let by_file = json!({ "$ref": format!("file://{}", target.display()) });
        let err = validate_instance(&by_file, &json!("anything"))
            .expect_err("a file:// $ref must not be read from disk");
        assert!(
            matches!(err, vti_common::error::AppError::Internal(_)),
            "the schema is at fault, not the instance: {err:?}"
        );

        // And the network case. It must be refused at compile, not attempted —
        // an unroutable address, so a regression that restores the resolver
        // shows up as a refusal that takes a connect timeout rather than a pass.
        let by_http = json!({ "$ref": "http://127.0.0.1:1/schema.json" });
        assert!(
            validate_instance(&by_http, &json!("anything")).is_err(),
            "an http:// $ref must not be fetched"
        );

        // An ordinary internal $ref still resolves — this removes remote
        // resolution, not $ref itself.
        let internal = json!({
            "$defs": { "name": { "type": "string" } },
            "properties": { "name": { "$ref": "#/$defs/name" } },
            "required": ["name"],
        });
        assert!(validate_instance(&internal, &json!({ "name": "ok" })).is_ok());
        assert!(validate_instance(&internal, &json!({ "name": 7 })).is_err());
    }
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

    /// A real schema compiles; a document that is not one is refused, and the
    /// refusal names the JSON Pointer into the bad keyword rather than saying
    /// only that something, somewhere, is wrong.
    #[test]
    fn check_schema_names_the_part_that_is_not_a_schema() {
        check_schema(&json!({
            "type": "object",
            "properties": { "level": { "type": "integer" } },
            "required": ["level"]
        }))
        .expect("a valid JSON Schema compiles");

        for (schema, expected_at) in [
            (json!({ "type": "not-a-type" }), "/type"),
            (json!({ "properties": "nope" }), "/properties"),
            (json!({ "required": "nope" }), "/required"),
            (
                json!({ "type": "object", "properties": { "level": { "type": "intiger" } } }),
                "/properties/level/type",
            ),
        ] {
            let detail = check_schema(&schema).expect_err("not a JSON Schema");
            assert!(
                detail.starts_with(&format!("at {expected_at}:")),
                "{schema} → {detail}"
            );
        }
    }

    /// JSON Schema accepts the bare booleans as schemas; `claimSchema` is
    /// `"type": "object"` in the register payload schema, so a non-object is
    /// refused before the compile would let it through.
    #[test]
    fn check_schema_refuses_a_non_object() {
        for (doc, named) in [
            (json!(true), "a boolean"),
            (json!("{}"), "a string"),
            (json!([{ "type": "object" }]), "an array"),
            (json!(null), "null"),
        ] {
            let detail = check_schema(&doc).expect_err("not an object");
            assert_eq!(detail, format!("expected a JSON object, found {named}"));
        }
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
