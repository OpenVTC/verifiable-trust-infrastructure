//! Executor-authored effects — what a task will actually do, computed by
//! dry-running the handler that is about to run it.
//!
//! Wire shape of `task-consent/_shared/0.1#Effect` and `#StatePin`.
//!
//! The point of these types is that a *payload* says what was asked for, while
//! only the code about to run knows what will *happen* — and it knows it only
//! against state the requester cannot see. A `webvh/dids/update` whose payload
//! adds one service endpoint also rotates the DID's update keys; that
//! consequence lives in the handler's semantics, not the payload's shape, so no
//! diff of the payload recovers it.
//!
//! An [`Effect`] is therefore produced by running the real handler in plan mode,
//! never by a second implementation that describes what the handler does. A
//! second implementation drifts, and when it drifts the human is confidently
//! misinformed while every signature still verifies.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One consequence of executing a task, authored by the executor.
///
/// `kind` is deliberately an open string: handlers evolve faster than any
/// enum, and an executor must be able to describe a consequence this crate
/// does not name. `summary` is what makes that safe — it is REQUIRED, it is
/// human-facing, and a consent surface is obliged to render it even for a
/// `kind` it does not recognise, so an unknown effect degrades to something
/// truthful rather than something invisible.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Effect {
    pub kind: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Map<String, Value>>,
}

impl Effect {
    /// An effect with only the members every surface can render.
    pub fn new(kind: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            summary: summary.into(),
            path: None,
            before: None,
            after: None,
            detail: None,
        }
    }

    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Prior value. Leave unset to mean "there was none" — an explicit JSON
    /// `null` is indistinguishable from absence on the wire, so anything the
    /// distinction matters for belongs in `summary`.
    pub fn before(mut self, before: Value) -> Self {
        self.before = Some(before);
        self
    }

    pub fn after(mut self, after: Value) -> Self {
        self.after = Some(after);
        self
    }

    pub fn detail(mut self, detail: Map<String, Value>) -> Self {
        self.detail = Some(detail);
        self
    }
}

/// The prior state a plan's effects were computed against.
///
/// Asserted at execution: a human in the loop makes the approval window minutes
/// wide, so the state can move underneath a pending approval and a lost update
/// is a real risk rather than a theoretical one.
///
/// This is the *wire* pin — what the approver is shown. An executor may hold
/// further, internal preconditions that it also re-checks at execution (the
/// webvh planner pins its key-derivation path counter, for instance); those are
/// its own business, since the approver trusts the executor and cannot verify
/// its internals in any case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatePin {
    /// Identifier of the pinned resource — usually the subject DID.
    pub resource: String,
    /// Opaque version of the prior state. Compared for equality, never ordered.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_before_is_omitted_not_null() {
        // The schema promises no null-vs-absent distinction; make sure we don't
        // accidentally emit one, since a surface would render it as a value.
        let e = Effect::new("documentChange", "Adds a service endpoint.")
            .at("/service/0")
            .after(json!({ "id": "#files" }));
        let v = serde_json::to_value(&e).unwrap();
        assert!(!v.as_object().unwrap().contains_key("before"));
        assert_eq!(v["after"], json!({ "id": "#files" }));
    }

    #[test]
    fn round_trips() {
        let e = Effect::new("keyRotation", "Rotates the update key.")
            .before(json!(["z6MkA"]))
            .after(json!(["z6MkB"]));
        let back: Effect = serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
        assert_eq!(e, back);
    }
}
