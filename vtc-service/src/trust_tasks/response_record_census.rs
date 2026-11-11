//! No served response that carries a bearer secret is kept in the
//! duplicate-execution record.
//!
//! The spine records a successful response so a redelivery of the same `id`
//! is answered with it (`vti_trust_task_server::Dispatcher::records_response`).
//! A response carrying a token or a secret must not be: the record would hold
//! it in plaintext for the acceptance window, and anyone holding a copy of the
//! request would be handed it again without the handler running. This census
//! walks every served version's published response schema and fails when one
//! that names such a member is still recorded.

use std::collections::BTreeSet;

use serde_json::Value;
use vti_specs::schema_index;

/// Response members that are bearer secrets. A name here, anywhere reachable
/// in a served response schema, puts that Type URI outside the record.
const SECRET_MEMBERS: &[&str] = &[
    "accessToken",
    "refreshToken",
    "setupSessionToken",
    "sessionToken",
    "claimCode",
    "secretAccessKey",
    "privateKeyMultibase",
    "sealedSecret",
    "transportToken",
    "resumeToken",
];

/// Every property name reachable from the schema root, following local
/// `#/$defs/…` references. `$defs` that the response never references (a
/// cleartext declared only for bindings, say) are not walked.
fn reachable_member_names(schema: &Value) -> BTreeSet<String> {
    let defs = schema.get("$defs").and_then(Value::as_object);
    let mut names = BTreeSet::new();
    let mut seen_defs = BTreeSet::new();
    let mut stack: Vec<&Value> = vec![schema];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                for (k, v) in map {
                    match k.as_str() {
                        // Walked only when referenced.
                        "$defs" => {}
                        "$ref" => {
                            if let Some(name) = v.as_str().and_then(|r| r.strip_prefix("#/$defs/"))
                                && seen_defs.insert(name.to_string())
                                && let Some(def) = defs.and_then(|d| d.get(name))
                            {
                                stack.push(def);
                            }
                        }
                        "properties" => {
                            if let Some(props) = v.as_object() {
                                names.extend(props.keys().cloned());
                            }
                            stack.push(v);
                        }
                        _ => stack.push(v),
                    }
                }
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    names
}

#[test]
fn the_walk_follows_references_and_skips_unreferenced_defs() {
    let schema = serde_json::json!({
        "$ref": "#/$defs/Response",
        "$defs": {
            "Response": {"properties": {"tokens": {"$ref": "#/$defs/Tokens"}}},
            "Tokens": {"properties": {"accessToken": {"type": "string"}}},
            "Unused": {"properties": {"secretAccessKey": {"type": "string"}}}
        }
    });
    let names = reachable_member_names(&schema);
    assert!(names.contains("accessToken"));
    assert!(names.contains("tokens"));
    assert!(!names.contains("secretAccessKey"));
}

#[test]
fn token_bearing_responses_are_not_recorded() {
    for uri in [
        super::auth_tasks::AUTHENTICATE_V0_3_TYPE,
        super::auth_tasks::REFRESH_V0_2_TYPE,
        super::install_tasks::CLAIM_FINISH_TYPE,
        super::install_tasks::CLAIM_FINISH_V0_3_TYPE,
        super::recognise_tasks::RECOGNISE_TYPE,
        super::backup_tasks::INITIATE_EXPORT_TYPE,
        super::backup_tasks::INITIATE_IMPORT_TYPE,
    ] {
        assert!(
            !super::records_response(uri),
            "{uri} carries a token and must not be recorded"
        );
    }
    // An ordinary result is still recorded, so a redelivery gets it back.
    assert!(super::records_response(super::auth_tasks::CHALLENGE_TYPE));
}

#[test]
fn no_recorded_response_carries_a_secret_member() {
    let served = super::discovery::served_uris();
    let mut checked = 0usize;
    let mut recorded_with_secret = Vec::new();
    for uri in served {
        let Some(schema) = schema_index::schema_for(&format!("{uri}#response")) else {
            continue;
        };
        let schema: Value =
            serde_json::from_str(schema).unwrap_or_else(|e| panic!("{uri}#response: {e}"));
        checked += 1;
        let names = reachable_member_names(&schema);
        let hits: Vec<&str> = SECRET_MEMBERS
            .iter()
            .copied()
            .filter(|m| names.contains(*m))
            .collect();
        if !hits.is_empty() && super::records_response(uri) {
            recorded_with_secret.push(format!("{uri} ({})", hits.join(", ")));
        }
    }
    assert!(
        checked > 100,
        "checked {checked} response schemas — the census is broken, not the code"
    );
    assert!(
        recorded_with_secret.is_empty(),
        "these served responses carry a token or secret member but are kept in \
         the duplicate-execution record, so a redelivery would be handed the \
         secret again. Add each to its module's `SECRET_RESPONSES`:\n  {}",
        recorded_with_secret.join("\n  ")
    );
}
