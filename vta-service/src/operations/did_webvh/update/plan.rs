//! What a `webvh/dids/update` would do, computed by running the real update
//! through to the point of its first write and stopping there.
//!
//! This is the plan half of a plan/apply split. It is not a description of the
//! update — it *is* the update, minus the commit: the same resolve, the same
//! chain load, the same key derivation, the same `didwebvh_rs::update_did` call
//! that mints the actual next log entry. A parallel implementation that
//! described what the handler does would drift, and when it drifted the human
//! approving it would be confidently misinformed while every signature still
//! verified.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::policy::effects::{Effect, StatePin};

/// The outcome of planning an update: everything an approver needs to see, plus
/// the preconditions the executor must re-assert before committing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlan {
    pub did: String,
    pub scid: String,

    /// Version the plan was computed against — the wire [`StatePin`].
    pub prior_version_id: String,
    /// Version the update would produce.
    pub new_version_id: String,

    pub prior_document: Value,
    pub new_document: Value,

    /// Update keys authorized to sign before this update.
    pub prior_update_keys: Vec<String>,
    /// Update keys that would be authorized after it. Differs from
    /// `prior_update_keys` whenever the document changes — that rotation is the
    /// consequence the payload does not mention.
    pub new_update_keys: Vec<String>,

    /// Pre-rotation commitments the update would publish.
    pub pre_rotation_count: u32,
    /// The commitments themselves — hashes of the keys that will be authorized
    /// to sign the *next* rotation.
    ///
    /// Under pre-rotation these are the only place the freshly-derived keys
    /// surface: `new_update_keys` carries the key *revealed* from the previous
    /// entry's commitment, not a new derivation. So this is what proves a plan's
    /// peeked derivation agrees with the allocation the real run performs.
    pub new_next_key_hashes: Vec<String>,

    /// BIP-32 group whose counter the derivation drew from.
    pub base_path: String,
    /// Value of that counter when the keys above were derived.
    ///
    /// The planner *peeks* the counter rather than allocating, so the plan is
    /// read-only — but a peek reserves nothing. If another allocation in the
    /// same context lands before this plan is applied, the real run derives
    /// different keys than the ones reported here. The executor re-checks this
    /// value before committing and refuses if it moved, which is what makes the
    /// keys an approver was shown the keys that actually execute.
    pub path_counter_pin: u32,
}

impl UpdatePlan {
    /// The wire state pin the approver is shown.
    pub fn state_pin(&self) -> StatePin {
        StatePin {
            resource: self.did.clone(),
            version: self.prior_version_id.clone(),
        }
    }

    /// Whether this update rotates the DID's update keys.
    pub fn rotates_update_keys(&self) -> bool {
        self.new_update_keys != self.prior_update_keys
    }

    /// Render the plan as the effects a consent surface shows.
    ///
    /// The key rotation and the pre-rotation refresh are the whole point. They
    /// are invisible in the request payload — a surface diffing the submitted
    /// document would show only the document change and silently hide the fact
    /// that the DID's controlling key is being replaced.
    pub fn to_effects(&self) -> Vec<Effect> {
        let mut effects = Vec::new();

        for change in document_changes(&self.prior_document, &self.new_document) {
            effects.push(change);
        }

        if self.rotates_update_keys() {
            effects.push(
                Effect::new(
                    "keyRotation",
                    "Rotates this DID's update key. Any change to the document rotates it — the \
                     current update key stops being able to authorize further changes.",
                )
                .before(json!(self.prior_update_keys))
                .after(json!(self.new_update_keys)),
            );
        }

        if self.pre_rotation_count > 0 {
            let mut detail = Map::new();
            detail.insert("commitments".into(), json!(self.pre_rotation_count));
            let plural = if self.pre_rotation_count == 1 {
                ""
            } else {
                "s"
            };
            effects.push(
                Effect::new(
                    "preRotationRefresh",
                    format!(
                        "Publishes {} fresh pre-rotation commitment{plural}, which will authorize \
                         the next rotation.",
                        self.pre_rotation_count
                    ),
                )
                .detail(detail),
            );
        }

        effects
    }
}

/// Top-level document diff, one effect per changed member.
///
/// Deliberately shallow: it names *which* members move and shows their before
/// and after, rather than synthesising a JSON-Pointer-per-leaf diff that reads
/// precisely but tells a human less. Depth here would be false precision — the
/// consequences that actually matter (the key rotation) are not in the document
/// at all.
fn document_changes(prior: &Value, next: &Value) -> Vec<Effect> {
    let (Some(prior), Some(next)) = (prior.as_object(), next.as_object()) else {
        // Not both objects — report wholesale rather than guess.
        if prior != next {
            return vec![
                Effect::new("documentChange", "Replaces the DID document.")
                    .before(prior.clone())
                    .after(next.clone()),
            ];
        }
        return vec![];
    };

    let mut keys: Vec<&String> = prior.keys().chain(next.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut effects = Vec::new();
    for key in keys {
        let before = prior.get(key);
        let after = next.get(key);
        if before == after {
            continue;
        }
        let summary = match (before, after) {
            (None, Some(_)) => format!("Adds `{key}` to the DID document."),
            (Some(_), None) => format!("Removes `{key}` from the DID document."),
            _ => format!("Changes `{key}` in the DID document."),
        };
        let mut effect = Effect::new("documentChange", summary).at(format!("/{key}"));
        if let Some(b) = before {
            effect = effect.before(b.clone());
        }
        if let Some(a) = after {
            effect = effect.after(a.clone());
        }
        effects.push(effect);
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> UpdatePlan {
        UpdatePlan {
            did: "did:webvh:QmScid:example.com:acme".into(),
            scid: "QmScid".into(),
            prior_version_id: "3-QmPrior".into(),
            new_version_id: "4-QmNext".into(),
            prior_document: json!({ "id": "did:webvh:QmScid:example.com:acme" }),
            new_document: json!({
                "id": "did:webvh:QmScid:example.com:acme",
                "service": [{ "id": "#files", "type": "FileStore" }]
            }),
            prior_update_keys: vec!["z6MkOld".into()],
            new_update_keys: vec!["z6MkNew".into()],
            pre_rotation_count: 2,
            new_next_key_hashes: vec!["QmHashA".into(), "QmHashB".into()],
            base_path: "m/1'/2'".into(),
            path_counter_pin: 7,
        }
    }

    /// The property the whole design turns on: a payload that adds a service
    /// endpoint must surface the key rotation it silently causes.
    #[test]
    fn a_document_change_surfaces_the_hidden_key_rotation() {
        let effects = plan().to_effects();
        let kinds: Vec<&str> = effects.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["documentChange", "keyRotation", "preRotationRefresh"]
        );

        let rotation = &effects[1];
        assert_eq!(rotation.before, Some(json!(["z6MkOld"])));
        assert_eq!(rotation.after, Some(json!(["z6MkNew"])));
        assert!(
            rotation.summary.contains("stops being able to authorize"),
            "the summary must say what the rotation costs the holder: {}",
            rotation.summary
        );
    }

    #[test]
    fn added_member_reports_no_before() {
        let effects = plan().to_effects();
        let doc = &effects[0];
        assert_eq!(doc.path.as_deref(), Some("/service"));
        assert!(doc.before.is_none(), "an added member has no prior value");
        assert!(doc.summary.starts_with("Adds `service`"));
    }

    #[test]
    fn no_rotation_when_keys_are_unchanged() {
        let mut p = plan();
        p.new_update_keys = p.prior_update_keys.clone();
        p.pre_rotation_count = 0;
        let kinds: Vec<String> = p.to_effects().iter().map(|e| e.kind.clone()).collect();
        assert_eq!(kinds, ["documentChange"]);
    }

    #[test]
    fn removal_reports_no_after() {
        let mut p = plan();
        std::mem::swap(&mut p.prior_document, &mut p.new_document);
        let doc = &p.to_effects()[0];
        assert!(
            doc.after.is_none(),
            "a removed member has no resulting value"
        );
        assert!(doc.summary.starts_with("Removes `service`"));
    }
}
