//! No dispatched response that carries a bearer secret is kept in the
//! duplicate-execution record.
//!
//! The spine records a successful response so a redelivery of the same `id` is
//! answered with it. A response carrying a token or a secret must not be: the
//! record would hold it for the acceptance window, and anyone holding a copy of
//! the request would be handed it again without the handler running. This
//! census walks every dispatched version's published response schema and fails
//! when one naming such a member is still recorded ([`super::records_response`]).

use std::collections::BTreeSet;

use serde_json::Value;
use vti_specs::schema_index;

/// Whether a response member's name says it may be a bearer secret: it names a
/// token or a secret, or ends in `code`.
fn looks_secret(member: &str) -> bool {
    let lower = member.to_ascii_lowercase();
    lower.contains("token") || lower.contains("secret") || lower.ends_with("code")
}

/// Members whose name [`looks_secret`] but that carry no bearer secret, by the
/// Type URI prefix they appear under: `(prefix, member, why)`.
const NOT_SECRET: &[(&str, &str, &str)] = &[
    (
        "https://trusttasks.org/spec/consent/list/",
        "nextSyncToken",
        "an incremental-sync cursor",
    ),
    (
        "https://trusttasks.org/spec/device/",
        "token",
        "a Play Integrity attestation, evidence about the device",
    ),
    (
        "https://trusttasks.org/spec/vault/",
        "secretKind",
        "the kind of secret an entry holds, never the secret",
    ),
    (
        "https://trusttasks.org/spec/external/accounts/",
        "secret",
        "whether and when the secret was set, never the secret",
    ),
    (
        "https://trusttasks.org/spec/external/accounts/",
        "tokenEndpoint",
        "where the account obtains tokens",
    ),
    (
        "https://trusttasks.org/spec/external/accounts/",
        "tokenScope",
        "the scope it asks for",
    ),
    (
        "https://trusttasks.org/spec/vta/pcs/",
        "tokenLabel",
        "a token label, public",
    ),
    (
        "https://trusttasks.org/spec/vta/pcs/",
        "tokenSerial",
        "a spent token serial, public once spent",
    ),
    (
        "https://trusttasks.org/spec/vta/pcs/",
        "tokensFree",
        "a count",
    ),
    (
        "https://trusttasks.org/spec/vta/pcs/",
        "tokensHeld",
        "a count",
    ),
    (
        "https://trusttasks.org/spec/rooms/",
        "code",
        "a host's or this specification's error code",
    ),
    (
        "https://trusttasks.org/spec/rooms/",
        "hostCode",
        "the host's trust-task-error code, unaltered",
    ),
    (
        "https://trusttasks.org/spec/vta/backup/",
        "importedSecretCount",
        "a count",
    ),
];

fn listed_as_not_secret(uri: &str, member: &str) -> bool {
    NOT_SECRET
        .iter()
        .any(|(prefix, m, _)| uri.starts_with(prefix) && *m == member)
}

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
fn the_backup_initiators_are_not_recorded() {
    for uri in super::BEARER_RESPONSES {
        assert!(
            !super::records_response(uri),
            "{uri} carries a transport token"
        );
    }
}

#[test]
fn no_recorded_response_carries_a_secret_member() {
    let mut checked = 0usize;
    let mut recorded_with_secret = Vec::new();
    for uri in super::dispatched_uris() {
        let Some(schema) = schema_index::schema_for(&format!("{uri}#response")) else {
            continue;
        };
        let schema: Value =
            serde_json::from_str(schema).unwrap_or_else(|e| panic!("{uri}#response: {e}"));
        checked += 1;
        let names = reachable_member_names(&schema);
        let hits: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|m| looks_secret(m) && !listed_as_not_secret(uri, m))
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
        "these dispatched responses carry a token, secret or code member but are kept \
         in the duplicate-execution record, so a redelivery would be handed it again. \
         Class the task as disclosing a secret, add it to `BEARER_RESPONSES`, or — if \
         the member is not a secret — add it to `NOT_SECRET` with the reason:\n  {}",
        recorded_with_secret.join("\n  ")
    );
}
