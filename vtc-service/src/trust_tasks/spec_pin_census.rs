//! Every Type URI this VTC serves is a version `vti-specs` pins.
//!
//! `vti_specs::schema_index` answers only for pinned versions, and the spine's
//! gates read its `None` as "nothing to check" — schema validation, the SPEC
//! §7.2 policy, the size bound — so an unpinned served URI fails open,
//! silently. Most served URIs come from a generated `Payload::TYPE_URI` and
//! cannot be unpinned; a string one can. The workspace-wide census (constants
//! and `TASK_*`) is `vta-service`'s `trust_tasks::spec_pin_census`.

use vti_specs::schema_index;

#[test]
fn every_served_uri_is_pinned() {
    let served = super::discovery::served_uris();
    assert!(
        served.len() > 100,
        "served {} URIs — the census is broken, not the code",
        served.len()
    );
    let unpinned: Vec<&str> = served
        .iter()
        .copied()
        // A framework specification (`trust-task-discovery`, …) cannot be
        // pinned: the runtime carries it, and `schema_index` answers from there.
        .filter(|uri| !uri.contains("/spec/trust-task-") && !schema_index::is_pinned(uri))
        .collect();
    assert!(
        unpinned.is_empty(),
        "this VTC serves Type URIs no `vti-specs-*` crate pins, so the dispatch \
         spine would validate nothing for them:\n  {}\n\n\
         Pin each with `trust-tasks -C vti-specs-<crate> add <slug>/<M.N>` and \
         commit the lock and the bundle (CLAUDE.md, \"Pinning a task version\").",
        unpinned.join("\n  ")
    );
}
