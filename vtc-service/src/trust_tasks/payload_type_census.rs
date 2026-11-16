//! Census: a handler reads its payload as the generated `vti_specs` type.
//!
//! `vta-sdk/tests/generated_wire_types_census.rs` refuses a hand-written type
//! whose doc summary names a generated task. It cannot see the other way a
//! second description of a payload gets in: a handler that validates the
//! document against the generated type and then parses the same JSON again
//! into a struct of its own (#2574). The REST era left about twenty of those —
//! `ListMembersQuery`, `UploadBody`, `IssueBody`, … — each a parallel shape
//! that could drift from the schema with nothing to notice.
//!
//! This reads every handler file in `trust_tasks/` and finds each payload parse
//! that names its type — `let body: T = match parse_payload(&doc)` and
//! `let body: T = match serde_json::from_value(without_ext(&doc))` — and
//! requires `T` to be a generated payload (`…Payload`).
//!
//! [`NOT_YET_GENERATED`] lists the parses whose type is still hand-written,
//! each with why. **It only shrinks**: converting one fails this census until
//! its entry goes too.

use std::fs;
use std::path::Path;

/// `(file, type)` parses whose type is not a generated payload yet.
const NOT_YET_GENERATED: &[(&str, &str)] = &[
    // The configuration document is the export's own model, shared with
    // `vtc/config/export`'s response and the backup bundle.
    (
        "config_tasks.rs",
        "crate::community::ops::config::ImportRequest",
    ),
    // The profile's storage-layer update, whose `Option` members keep
    // "absent" and "clear" apart.
    (
        "config_tasks.rs",
        "crate::community::CommunityProfileUpdate",
    ),
    // The SDK's join and credential-exchange bodies, older than their
    // generated modules; tracked by the SDK's census.
    ("credential_exchange.rs", "PresentBody"),
    ("credential_exchange.rs", "RequestBody"),
    ("join_tasks.rs", "JoinRequestStatusBody"),
    ("join_tasks.rs", "JoinRequestSubmitBody"),
    ("join_tasks.rs", "jr::SelfRemoveBody"),
    ("member_admin_tasks.rs", "MemberVmcBody"),
    (
        "surface_tasks.rs",
        "vta_sdk::protocols::vetting::AutoGrantConfig",
    ),
];

/// Every `(file, type)` payload parse in the handler files.
fn parses() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust_tasks");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("trust_tasks is readable") {
        let path = entry.expect("a dir entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "payload_type_census.rs" {
            continue;
        }
        let src = fs::read_to_string(&path).expect("a handler file is readable");
        // A statement may wrap after `=`; read it joined.
        let joined: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
        for marker in [
            "= match parse_payload(&doc)",
            "= match serde_json::from_value(without_ext(&doc))",
        ] {
            let mut rest = joined.as_str();
            while let Some(at) = rest.find(marker) {
                let before = &rest[..at];
                if let Some(colon) = before.rfind(": ")
                    && before[..colon].rfind("let ").is_some()
                {
                    out.push((name.clone(), before[colon + 2..].trim().to_string()));
                }
                rest = &rest[at + marker.len()..];
            }
        }
    }
    out.sort();
    out
}

fn is_generated(ty: &str) -> bool {
    ty.ends_with("Payload")
}

/// No handler parses its payload into a hand-written type it does not have to.
#[test]
fn handlers_parse_payloads_as_the_generated_types() {
    let found = parses();
    assert!(
        found.len() > NOT_YET_GENERATED.len(),
        "the scan found {} parses — it has stopped reading the handlers",
        found.len()
    );
    let offending: Vec<String> = found
        .iter()
        .filter(|(file, ty)| {
            !is_generated(ty) && !NOT_YET_GENERATED.contains(&(file.as_str(), ty.as_str()))
        })
        .map(|(file, ty)| format!("{file}: {ty}"))
        .collect();
    assert!(
        offending.is_empty(),
        "these handlers parse a payload into a hand-written type — take the generated \
         `vti_specs` payload (validated by `parse_spec_payload`) instead, and read a member \
         the generated type folds (absent vs empty) from the received JSON \
         (`crate::wire::sent`):\n  {}",
        offending.join("\n  ")
    );
}

/// [`NOT_YET_GENERATED`] only shrinks: an entry whose parse is gone goes too.
#[test]
fn the_baseline_only_shrinks() {
    let found = parses();
    let stale: Vec<String> = NOT_YET_GENERATED
        .iter()
        .filter(|(file, ty)| !found.iter().any(|(f, t)| f == file && t == ty))
        .map(|(file, ty)| format!("{file}: {ty}"))
        .collect();
    assert!(
        stale.is_empty(),
        "these entries name a parse that no longer exists — remove them:\n  {}",
        stale.join("\n  ")
    );
}
