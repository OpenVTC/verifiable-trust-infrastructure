//! Compiled JSON Schemas for Trust Task payloads, compiled once per process.
//!
//! `trust_tasks_rs::validate::against_schema` parses and compiles the schema on
//! **every** call — tens of KB of JSON and every `pattern` regex in it — before
//! validating a payload that is usually a few hundred bytes (#2622). The VTA
//! would run that per dispatched task on every transport, and the SDK again per
//! send.
//!
//! This module is a thin wrapper over `trust-tasks-rs`'s own cache,
//! [`SchemaValidator`]: one process-wide instance ([`SCHEMAS`]) that every crate
//! in the workspace checks through, so a schema is compiled once however many
//! call sites validate against it. Validation semantics, the `jsonschema`
//! release and the error text are `trust-tasks-rs`'s, by construction.
//! [`check_payload`] is `ValidatedPayload::validate_value`, which shares
//! `trust-tasks-rs`'s internal instance.
//!
//! The SPEC §12.3 caution on `against_schema` applies unchanged: only hand this
//! schemas whose source is trusted (the generated `Payload::PAYLOAD_SCHEMA` and
//! `vti_specs::schema_index::schema_for` constants).

use serde_json::Value;
use trust_tasks_rs::validate::ValidatedPayload;
pub use trust_tasks_rs::validate::{SchemaValidator, ValidationError};

/// One or more problems found validating a value against a schema.
pub type SchemaError = ValidationError;

/// The process-wide compiled-schema cache.
pub static SCHEMAS: SchemaValidator = SchemaValidator::new();

/// Validate `value` against `schema_json` — `against_schema`, without the
/// per-call compile.
///
/// # Errors
///
/// The schema does not parse or compile, or `value` does not conform.
pub fn check(schema_json: &str, value: &Value) -> Result<(), SchemaError> {
    SCHEMAS.check(schema_json, value)
}

/// Validate `value` against payload type `P`'s embedded schema. A type that
/// embeds no schema passes.
///
/// # Errors
///
/// `value` does not conform to `P`'s schema.
pub fn check_payload<P: trust_tasks_rs::Payload>(value: &Value) -> Result<(), SchemaError> {
    P::validate_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &str = r#"{
        "type": "object",
        "required": ["id"],
        "additionalProperties": false,
        "properties": { "id": { "type": "string", "pattern": "^[a-z]+$" } }
    }"#;

    #[test]
    fn agrees_with_against_schema_on_pass_and_fail_and_error_text() {
        for value in [
            json!({ "id": "abc" }),
            json!({ "id": "ABC" }),
            json!({ "id": "abc", "extra": 1 }),
            json!({}),
            json!(null),
        ] {
            let ours = check(SCHEMA, &value).map_err(|e| e.to_string());
            let theirs =
                trust_tasks_rs::validate::against_schema(SCHEMA, &value).map_err(|e| e.to_string());
            assert_eq!(ours, theirs, "for {value}");
        }
    }

    #[test]
    fn a_bad_schema_is_reported() {
        let e = check("{ not json", &json!({})).unwrap_err();
        assert!(e.to_string().starts_with("schema JSON did not parse"));
    }

    #[test]
    fn every_pinned_schema_compiles_and_agrees_on_an_empty_object() {
        for uri in vti_specs::schema_index::type_uris() {
            let Some(schema) = vti_specs::schema_index::schema_for(uri) else {
                continue;
            };
            let ours = check(schema, &json!({})).map_err(|e| e.to_string());
            let theirs = trust_tasks_rs::validate::against_schema(schema, &json!({}))
                .map_err(|e| e.to_string());
            assert_eq!(ours, theirs, "{uri}");
        }
    }
}
