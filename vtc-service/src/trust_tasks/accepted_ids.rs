//! The accepted-document-id record — **VTI-OPS-025 … 027**, SPEC §7.2 item 11.
//!
//! # What it is for
//!
//! A signed Trust Task document is durable evidence of intent, and durable
//! evidence is replayable unless something remembers it. Once this service has
//! accepted a document with a given `id` for execution, the same document
//! arriving again **MUST NOT** cause the consequential effect a second time,
//! and a *different* document under that `id` **MUST** be refused with
//! `idConflict`. That is item 11, and VTI-OPS-025/-026 are the same rule in the
//! VTI specification's words: every document carries a unique identifier, and
//! one already accepted within the acceptance window is refused.
//!
//! # Why it is in the store, and not in a map
//!
//! **VTI-OPS-027**: "The record of accepted document identifiers MUST be shared
//! across every binding a node exposes. A document accepted on one binding MUST
//! NOT be acceptable on another." Its rationale is the whole reason this module
//! exists:
//!
//! > A document captured from one binding — a log, a proxy, a stored message —
//! > is a well-formed, correctly signed, correctly addressed document, and the
//! > second binding has no reason to doubt it. Where the two bindings do not
//! > share a record, the node's replay protection is exactly as good as its
//! > least-used transport.
//!
//! Until #1641 phase 2 the record was a process-local `InMemoryReplayGuard`
//! reachable only from [`crate::trust_tasks::dispatch_trust_task_core`]. That
//! is adequate while the dispatcher is the only door. It stops being adequate
//! the moment a task is served *both* on the dispatcher and on its bearer-JWT
//! REST route — which is exactly what phase 2 does, 49 times. The record has to
//! be shared **before** the first task moves, or the migration itself opens the
//! hole it is meant to close: the attacker replays on the door that is not
//! keeping a record.
//!
//! So the record lives in [`crate::store::keyspaces::ACCEPTED_IDS`], where any
//! binding in this process can consult it: the document dispatcher today, a
//! REST route tomorrow. Two properties fall out for free — it survives a
//! restart, which the in-memory map did not, and it is not capacity-evicted,
//! which the in-memory map was (a burst of distinct documents could push a live
//! record out before its deadline and let a replay through).
//!
//! # Where the implementation is
//!
//! In `vti_trust_task_server::accepted_store`, shared with the VTA, which kept
//! a process-local guard until it adopted this one. Rows are unchanged
//! (`accepted:<id>`), so the move needs no migration. This module names it for
//! this crate and pins the fallback retention against this service's window.

/// What the record says about a document offered for execution.
pub(crate) use vti_trust_task_server::Acceptance;
/// The store-backed accepted-id record, over
/// [`crate::store::keyspaces::ACCEPTED_IDS`].
pub(crate) use vti_trust_task_server::StoreAcceptedIds as AcceptedIds;
/// Drop every record whose retention deadline has passed. Runs on the
/// retention sweeper's tick.
pub(crate) use vti_trust_task_server::accepted_store::sweep_expired;

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use vti_trust_task_server::FALLBACK_RETENTION_SECS;

    /// The fallback retention the record applies when a caller bounds nothing
    /// must not be shorter than the window this service accepts a document in
    /// — a record dropped while its document is still executable is a replay
    /// that executes twice.
    #[test]
    fn fallback_retention_matches_the_acceptance_window() {
        let policy = crate::trust_tasks::freshness_policy();
        let window = policy.max_age.expect("the window is set") + policy.skew;
        assert_eq!(
            TimeDelta::seconds(FALLBACK_RETENTION_SECS),
            window,
            "FALLBACK_RETENTION_SECS must track freshness_policy()'s window"
        );
    }
}
