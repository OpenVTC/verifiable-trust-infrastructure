//! Generated Trust Task wire types: `hcp/*` (the Human Context Protocol).
//!
//! `build.rs` generates one module per version `trust-tasks.lock` pins, at the
//! path the prebuilt `trust_tasks_rs::specs` gave it, plus `schema_index` over
//! exactly those versions: the `hcp/*` 0.1 tasks the VTA's HCP Provider speaks
//! in V0 (`vta-hcp`, `vta-service` feature `hcp`; task A1 of
//! `docs/05-design-notes/hcp-tasks.md`). `vti-specs` re-exports it as
//! `vti_specs::hcp` and merges its index. The suite is `draft`, so a version
//! may change in place upstream; the lock's digests are what this crate
//! builds, and `trust-tasks -C vti-specs-hcp check` says whether they still
//! match. See `vti-specs`'s crate docs for how to pin a version.

// The generated file carries its own lint allowances (typify's output), and
// superseded versions keep their `#[deprecated]`, so a caller still on one
// hears about it.
include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
