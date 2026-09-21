//! What the community asks an applicant to tell it about themselves.
//!
//! One row in the `community` keyspace at [`REQUESTED_ATTRIBUTES_STORAGE_KEY`],
//! beside the branding, published as `requestedAttributes` on
//! `join-requests/manifest/0.2` and answered as `attributes` on
//! `join-requests/submit/0.2`. The shape is the manifest's own generated item,
//! so what an admin stores is exactly what an applicant is shown.
//!
//! # Self-asserted, and treated as such
//!
//! An answer is the applicant's own statement, bound to them by the
//! submission's proof and attested by nobody. It is stored with the request
//! and shown to reviewers as what the applicant said; it is never fed to the
//! join policy as evidence. A community that needs an attested value asks for a
//! credential in a criterion instead.
//!
//! # Ask only for what is asked
//!
//! A submission answering a type the community does not request is refused, not
//! trimmed: a value accepted "just in case" is personal data held for no stated
//! purpose, and trimming it silently would hide from the applicant that their
//! client over-shared.

use std::collections::BTreeSet;

use serde_json::Value;
use vta_sdk::protocols::join_requests::manifest::v0_2::ResponseRequestedAttributesItem as RequestedAttribute;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Storage key in the `community` keyspace, beside the branding and backed up
/// with it.
pub const REQUESTED_ATTRIBUTES_STORAGE_KEY: &[u8] = b"community/requested-attributes";

/// The published cap (`requestedAttributes.maxItems`).
pub const MAX_REQUESTED: usize = 32;

/// What the community asks for; empty when it asks for nothing.
pub async fn load_requested(ks: &KeyspaceHandle) -> Result<Vec<RequestedAttribute>, AppError> {
    match ks.get_raw(REQUESTED_ATTRIBUTES_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("requested attributes decode: {e}"))),
        None => Ok(Vec::new()),
    }
}

/// Replace what the community asks for. Refuses more than
/// [`MAX_REQUESTED`] entries and any type asked for twice — two answers to one
/// question is no answer. An empty list removes the row, so the manifest asks
/// for nothing.
pub async fn store_requested(
    ks: &KeyspaceHandle,
    requested: &[RequestedAttribute],
) -> Result<(), AppError> {
    if requested.len() > MAX_REQUESTED {
        return Err(AppError::Validation(format!(
            "at most {MAX_REQUESTED} requested attributes; {} given",
            requested.len()
        )));
    }
    let mut seen = BTreeSet::new();
    if let Some(dup) = requested
        .iter()
        .map(|r| r.type_.as_str())
        .find(|t| !seen.insert(*t))
    {
        return Err(AppError::Validation(format!(
            "`{dup}` is requested twice; ask for each attribute once"
        )));
    }
    if requested.is_empty() {
        ks.remove(REQUESTED_ATTRIBUTES_STORAGE_KEY.to_vec()).await?;
        return Ok(());
    }
    let key = String::from_utf8(REQUESTED_ATTRIBUTES_STORAGE_KEY.to_vec()).expect("key is ASCII");
    ks.insert(key, &requested.to_vec()).await
}

/// One answer an applicant gave: a claim type and its value.
pub type Answer = (String, Value);

/// Why a set of answers does not fit what the community asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswersRefused {
    /// Required types with no answer.
    Missing(Vec<String>),
    /// Answered types the community does not ask for.
    Unrequested(Vec<String>),
}

/// Check `answers` against `requested`. Unrequested is reported first: an
/// applicant whose client over-shared should be told that before being asked
/// for more.
pub fn check_answers(
    requested: &[RequestedAttribute],
    answers: &[Answer],
) -> Result<(), AnswersRefused> {
    let asked: BTreeSet<&str> = requested.iter().map(|r| r.type_.as_str()).collect();
    let given: BTreeSet<&str> = answers.iter().map(|(t, _)| t.as_str()).collect();
    let unrequested: Vec<String> = given
        .iter()
        .filter(|t| !asked.contains(*t))
        .map(|t| (*t).to_string())
        .collect();
    if !unrequested.is_empty() {
        return Err(AnswersRefused::Unrequested(unrequested));
    }
    let missing: Vec<String> = requested
        .iter()
        .filter(|r| r.required && !given.contains(r.type_.as_str()))
        .map(|r| r.type_.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(AnswersRefused::Missing(missing));
    }
    Ok(())
}

/// The types added and removed between two lists, for the audit record.
#[must_use]
pub fn diff(
    before: &[RequestedAttribute],
    after: &[RequestedAttribute],
) -> (Vec<String>, Vec<String>) {
    let b: BTreeSet<String> = before.iter().map(|r| r.type_.to_string()).collect();
    let a: BTreeSet<String> = after.iter().map(|r| r.type_.to_string()).collect();
    (
        a.difference(&b).cloned().collect(),
        b.difference(&a).cloned().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(t: &str, required: bool) -> RequestedAttribute {
        serde_json::from_value(serde_json::json!({ "type": t, "required": required })).unwrap()
    }
    fn ans(t: &str) -> Answer {
        (t.to_string(), serde_json::json!("x"))
    }

    #[test]
    fn required_answers_are_needed_and_optional_ones_are_not() {
        let asked = [ask("name.display", true), ask("address.country", false)];
        assert_eq!(check_answers(&asked, &[ans("name.display")]), Ok(()));
        assert_eq!(
            check_answers(&asked, &[ans("address.country")]),
            Err(AnswersRefused::Missing(vec!["name.display".into()]))
        );
    }

    #[test]
    fn an_answer_nobody_asked_for_is_refused_first() {
        let asked = [ask("name.display", true)];
        assert_eq!(
            check_answers(&asked, &[ans("person.birthDate")]),
            Err(AnswersRefused::Unrequested(vec!["person.birthDate".into()]))
        );
        // A community asking for nothing takes nothing.
        assert_eq!(
            check_answers(&[], &[ans("name.display")]),
            Err(AnswersRefused::Unrequested(vec!["name.display".into()]))
        );
        assert_eq!(check_answers(&[], &[]), Ok(()));
    }

    #[test]
    fn required_defaults_to_true_on_the_wire() {
        let r: RequestedAttribute =
            serde_json::from_value(serde_json::json!({ "type": "name.display" })).unwrap();
        assert!(r.required);
    }
}
