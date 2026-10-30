//! Generated Trust Task wire types: `vta/*`.
//!
//! `build.rs` generates one module per version `trust-tasks.lock` pins, at the
//! path the prebuilt `trust_tasks_rs::specs` gave it, plus `schema_index` over
//! exactly those versions. Depend on `vti-specs` (or `vta_sdk::specs`), which
//! re-exports every family and merges the indexes, unless a crate must stay
//! this light. See `vti-specs`'s crate docs for how to pin a version.

// The generated file carries its own lint allowances (typify's output), and
// superseded versions keep their `#[deprecated]`, so a caller still on one
// hears about it.
include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
