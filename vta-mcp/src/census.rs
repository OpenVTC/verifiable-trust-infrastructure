//! This bridge's half of the guard census.
//!
//! `vti-mcp-common` holds every pinned request Type URI to a classified verb.
//! The VTA's dispatch table is a different set — it carries the framework
//! specifications (`trust-task-discovery`, …) that cannot be pinned, and the
//! migration-window versions still served — so every URI the generic
//! `vta_call` tool can reach is held here as well. A new verb landing in the
//! SDK catalog fails this test rather than quietly defaulting to `Mutating`
//! forever.

#[test]
fn every_dispatchable_uri_has_a_known_verb() {
    vti_mcp_common::guard::assert_every_verb_is_known(vta_sdk::trust_tasks::dispatch_routed_uris());
}
