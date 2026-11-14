//! Compiled JSON Schemas for Trust Task payloads, compiled once per process.
//!
//! `trust_tasks_rs::validate::against_schema` (and `ValidatedPayload::validate_value`,
//! which calls it) parses and compiles the schema on **every** call — tens of KB of
//! JSON and every `pattern` regex in it — before validating a payload that is usually
//! a few hundred bytes (#2622). The VTA runs that per dispatched task on every
//! transport, and the SDK again per send.
//!
//! The schemas are `&'static str` constants generated into the `vti-specs-*` crates
//! (`Payload::PAYLOAD_SCHEMA`, `vti_specs::schema_index::schema_for`), so they never
//! move: [`check`] caches the compiled validator by the schema text's address and
//! length, and a document pays for evaluation only.
//!
//! Validation semantics are exactly `against_schema`'s: the same `jsonschema`
//! release `trust-tasks-rs` 0.37 compiles with, draft 2020-12, and the same error
//! text ([`SchemaError`]'s `Display` matches `ValidationError`'s). `trust-tasks-rs`
//! 0.38 ships the same cache as `validate::SchemaValidator`; when the workspace
//! moves to it (it moves in lockstep with `affinidi-tdk`), this module becomes a
//! thin wrapper over it.
//!
//! The SPEC §12.3 caution on `against_schema` applies unchanged: only hand this
//! schemas whose source is trusted. Taking `&'static str` keeps that true here.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock, RwLock};

use jsonschema_trust_tasks as jsonschema;
use serde_json::Value;

/// A schema compiled once, to validate any number of values against.
///
/// Opaque, so the `jsonschema` release behind it is not part of this crate's API.
#[derive(Clone)]
pub struct CompiledSchema(Arc<jsonschema::Validator>);

impl fmt::Debug for CompiledSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledSchema").finish_non_exhaustive()
    }
}

impl CompiledSchema {
    /// Compile a schema value under JSON Schema draft 2020-12.
    pub fn compile(schema: &Value) -> Result<Self, SchemaError> {
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(schema)
            .map(|v| Self(Arc::new(v)))
            .map_err(|e| SchemaError::new(ErrorKind::SchemaCompile, vec![e.to_string()]))
    }

    /// Parse and compile a schema's JSON text.
    pub fn compile_str(schema_json: &str) -> Result<Self, SchemaError> {
        let value: Value = serde_json::from_str(schema_json)
            .map_err(|e| SchemaError::new(ErrorKind::SchemaParse, vec![e.to_string()]))?;
        Self::compile(&value)
    }

    /// Validate `value`, collecting every error in source order.
    pub fn check(&self, value: &Value) -> Result<(), SchemaError> {
        let messages: Vec<String> = self.0.iter_errors(value).map(|e| e.to_string()).collect();
        if messages.is_empty() {
            Ok(())
        } else {
            Err(SchemaError::new(ErrorKind::Instance, messages))
        }
    }
}

/// Address and length of a `&'static str`: a static never moves or changes, so
/// the pair names its content for the life of the process.
type StaticKey = (usize, usize);

static COMPILED: LazyLock<RwLock<HashMap<StaticKey, CompiledSchema>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// The compiled form of `schema_json`, compiled on first use and kept.
///
/// A schema that fails to parse or compile is not cached; every call reports it
/// (a generated schema never does — the build compiles each one in a test).
pub fn compiled(schema_json: &'static str) -> Result<CompiledSchema, SchemaError> {
    let key = (schema_json.as_ptr() as usize, schema_json.len());
    // A poisoned lock only means a panic elsewhere mid-insert of a whole entry;
    // the map itself is never left half-written, so keep using it.
    if let Some(hit) = COMPILED.read().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return Ok(hit.clone());
    }
    // Compiled outside the lock: two first callers may both compile, and one
    // result wins. That costs one extra compile once, never a stall.
    let fresh = CompiledSchema::compile_str(schema_json)?;
    let mut map = COMPILED.write().unwrap_or_else(|p| p.into_inner());
    Ok(map.entry(key).or_insert(fresh).clone())
}

/// Validate `value` against `schema_json` — `against_schema`, without the
/// per-call compile.
pub fn check(schema_json: &'static str, value: &Value) -> Result<(), SchemaError> {
    compiled(schema_json)?.check(value)
}

/// Validate `value` against payload type `P`'s embedded schema — what
/// `ValidatedPayload::validate_value` does, without the per-call compile. A
/// type that embeds no schema passes, as there.
pub fn check_payload<P: trust_tasks_rs::Payload>(value: &Value) -> Result<(), SchemaError> {
    match P::PAYLOAD_SCHEMA {
        Some(schema) => check(schema, value),
        None => Ok(()),
    }
}

/// One or more problems found validating a value against a schema.
///
/// `Display` reads as `trust_tasks_rs::validate::ValidationError`'s does.
#[derive(Debug)]
pub struct SchemaError {
    kind: ErrorKind,
    messages: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum ErrorKind {
    SchemaParse,
    SchemaCompile,
    Instance,
}

impl SchemaError {
    fn new(kind: ErrorKind, messages: Vec<String>) -> Self {
        Self { kind, messages }
    }

    /// The collected per-error messages from the validator, in source order.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.kind {
            ErrorKind::SchemaParse => "schema JSON did not parse",
            ErrorKind::SchemaCompile => "schema did not compile",
            ErrorKind::Instance => "payload failed schema validation",
        };
        write!(f, "{label}: {}", self.messages.join("; "))
    }
}

impl std::error::Error for SchemaError {}

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
    fn compiles_each_schema_once() {
        let a = compiled(SCHEMA).unwrap();
        let b = compiled(SCHEMA).unwrap();
        assert!(
            Arc::ptr_eq(&a.0, &b.0),
            "second call reuses the first compile"
        );
    }

    #[test]
    fn a_bad_schema_is_reported_not_cached() {
        const BAD: &str = "{ not json";
        let e = check(BAD, &json!({})).unwrap_err();
        assert!(e.to_string().starts_with("schema JSON did not parse"));
        let key = (BAD.as_ptr() as usize, BAD.len());
        assert!(!COMPILED.read().unwrap().contains_key(&key));
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
