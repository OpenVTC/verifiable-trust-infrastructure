//! Executor preconditions carried through the plan → approve → execute
//! pipeline.
//!
//! These live here (rather than in `vta-service`'s trust-task planner) so both
//! the planner and the `vta-policy` consent model can name them without a
//! cross-crate cycle. Pure serialisable data — no behaviour.

/// Preconditions the executor checks for itself before committing.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Guards {
    /// The BIP-32 derivation-path counter the webvh planner peeked, and the
    /// group it peeked it from.
    ///
    /// A peek reserves nothing. If another allocation in the same context lands
    /// while a human is deciding, the real run derives *different keys* than the
    /// ones the approver was shown — so the counter has to be pinned and
    /// re-checked, or the approval authorizes a rotation to a key that never
    /// existed.
    pub webvh_path_counter: Option<WebvhPathCounter>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebvhPathCounter {
    pub base_path: String,
    pub counter: u32,
}
