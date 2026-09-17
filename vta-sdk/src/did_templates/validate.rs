//! Structural + semantic validation for [`DidTemplate`].
//!
//! Runs automatically on `from_json` / `load_file` / `load_embedded`. Also
//! exposed via [`DidTemplate::validate`] for CLI linters that want to re-check
//! a template without re-parsing.

use std::collections::HashSet;

use serde_json::Value;

use super::{
    DidTemplate, RESERVED_VARS, SCHEMA_VERSION_MAX, SCHEMA_VERSION_MIN, TemplateError,
    render::walk_placeholders,
};

pub(super) fn validate(tpl: &DidTemplate) -> Result<(), TemplateError> {
    check_schema_version(tpl)?;
    check_name(&tpl.name)?;
    check_kind(&tpl.kind)?;
    check_reserved_vars(tpl)?;
    check_var_overlap(tpl)?;
    check_document_has_id_placeholder(&tpl.document)?;
    check_placeholders_declared(tpl)?;
    check_key_slots(tpl)?;
    Ok(())
}

/// The `keys` block: only at `schemaVersion` 2+, and every slot must name at
/// least one algorithm this build recognises.
fn check_key_slots(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let Some(declared) = &tpl.keys else {
        return Ok(());
    };

    if tpl.schema_version < super::SCHEMA_VERSION_KEYS_BLOCK {
        return Err(TemplateError::Invalid(format!(
            "`keys` requires schemaVersion {} or later, but this template declares {}; a v1 \
             template's keys are the implicit Ed25519/X25519 pair",
            super::SCHEMA_VERSION_KEYS_BLOCK,
            tpl.schema_version,
        )));
    }

    let mut used = HashSet::new();
    walk_placeholders(&tpl.document, &mut used);

    for (slot, spec) in declared {
        if slot.is_empty()
            || !slot
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(TemplateError::Invalid(format!(
                "key slot '{slot}' must match [a-z0-9-]+ — the name becomes the placeholder \
                 `{{{}}}`",
                DidTemplate::slot_var(slot),
            )));
        }

        // An empty list is refused rather than read as "anything". A template
        // expressing no preference would inherit whatever the implementation
        // defaulted to, which is how a deployment meant to be post-quantum
        // quietly mints classical keys.
        if spec.algorithms.is_empty() {
            return Err(TemplateError::Invalid(format!(
                "key slot '{slot}' names no algorithms; list them most-preferred first"
            )));
        }

        for algorithm in &spec.algorithms {
            let parsed: Result<crate::keys::KeyType, _> =
                serde_json::from_value(serde_json::Value::String(algorithm.clone()));
            let Ok(key_type) = parsed else {
                return Err(TemplateError::Invalid(format!(
                    "key slot '{slot}' names algorithm '{algorithm}', which this build does not \
                     know"
                )));
            };

            // A signing algorithm cannot agree a key and vice versa. Caught
            // here because the alternative is a DID document that looks
            // well-formed and whose `keyAgreement` entry nothing can use.
            let usable = match spec.purpose {
                super::KeyPurpose::Signing => !matches!(key_type, crate::keys::KeyType::X25519),
                super::KeyPurpose::KeyAgreement => {
                    matches!(key_type, crate::keys::KeyType::X25519)
                }
            };
            if !usable {
                return Err(TemplateError::Invalid(format!(
                    "key slot '{slot}' is declared for {:?} but names '{algorithm}', which \
                     cannot serve that purpose",
                    spec.purpose,
                )));
            }
        }

        // A declared slot that the document never uses is the failure this
        // block exists to prevent, wearing a different hat: the template
        // announces a post-quantum key, the VTA mints one, and the DID document
        // does not publish it — so every verifier still sees only the classical
        // key and the deployment believes it migrated.
        //
        // Minting a key nothing publishes is also a silent cost: it consumes a
        // derivation path forever.
        let var = DidTemplate::slot_var(slot);
        if !used.contains(&var) {
            return Err(TemplateError::Invalid(format!(
                "key slot '{slot}' is declared but `{{{var}}}` never appears in the document, \
                 so the key would be minted and never published"
            )));
        }
    }

    // And the converse: a slot placeholder in the document that no slot
    // declares would render as an unsubstituted literal.
    for var in &used {
        let Some(slot) = var.strip_suffix("_KEY_MB") else {
            continue;
        };
        let slot = slot.to_ascii_lowercase().replace('_', "-");
        if !declared.contains_key(&slot) {
            return Err(TemplateError::Invalid(format!(
                "document uses `{{{var}}}` but no key slot '{slot}' is declared"
            )));
        }
    }
    Ok(())
}

fn check_schema_version(tpl: &DidTemplate) -> Result<(), TemplateError> {
    if tpl.schema_version < SCHEMA_VERSION_MIN || tpl.schema_version > SCHEMA_VERSION_MAX {
        return Err(TemplateError::UnsupportedSchema {
            found: tpl.schema_version,
            min: SCHEMA_VERSION_MIN,
            max: SCHEMA_VERSION_MAX,
        });
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), TemplateError> {
    if name.is_empty() || name.len() > 64 {
        return Err(TemplateError::Invalid(format!(
            "name '{name}' must be 1..=64 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(TemplateError::Invalid(format!(
            "name '{name}' must match [a-z0-9-]+"
        )));
    }
    Ok(())
}

fn check_kind(kind: &str) -> Result<(), TemplateError> {
    if kind.is_empty() {
        return Err(TemplateError::Invalid("kind must not be empty".into()));
    }
    Ok(())
}

fn check_reserved_vars(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let reserved: HashSet<&str> = RESERVED_VARS.iter().copied().collect();
    for v in &tpl.required_vars {
        if reserved.contains(v.as_str()) {
            return Err(TemplateError::ReservedVar(v.clone()));
        }
    }
    for k in tpl.optional_vars.keys() {
        if reserved.contains(k.as_str()) {
            return Err(TemplateError::ReservedVar(k.clone()));
        }
    }
    Ok(())
}

fn check_var_overlap(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let required: HashSet<&str> = tpl.required_vars.iter().map(String::as_str).collect();
    for k in tpl.optional_vars.keys() {
        if required.contains(k.as_str()) {
            return Err(TemplateError::Invalid(format!(
                "variable '{k}' appears in both requiredVars and optionalVars"
            )));
        }
    }
    Ok(())
}

fn check_document_has_id_placeholder(doc: &Value) -> Result<(), TemplateError> {
    let id = doc.get("id").and_then(Value::as_str).ok_or_else(|| {
        TemplateError::Invalid(
            "document.id is missing or not a string — must be the `{DID}` placeholder".into(),
        )
    })?;
    if !id.contains("{DID}") {
        return Err(TemplateError::Invalid(format!(
            "document.id ('{id}') must contain the `{{DID}}` placeholder"
        )));
    }
    Ok(())
}

/// Every placeholder found in the document must be either declared (required
/// or optional) or a reserved ambient name. Unknown placeholders fail fast at
/// validation time rather than silently producing an unresolved render error.
fn check_placeholders_declared(tpl: &DidTemplate) -> Result<(), TemplateError> {
    let declared: HashSet<String> = tpl
        .required_vars
        .iter()
        .cloned()
        .chain(tpl.optional_vars.keys().cloned())
        .chain(RESERVED_VARS.iter().map(|s| s.to_string()))
        .collect();

    let mut found = HashSet::new();
    walk_placeholders(&tpl.document, &mut found);

    let undeclared: Vec<String> = found.difference(&declared).cloned().collect();
    if !undeclared.is_empty() {
        let mut names = undeclared;
        names.sort();
        return Err(TemplateError::Invalid(format!(
            "undeclared placeholder(s) {{ {} }} in document — add them to requiredVars or optionalVars",
            names.join(", ")
        )));
    }
    Ok(())
}
