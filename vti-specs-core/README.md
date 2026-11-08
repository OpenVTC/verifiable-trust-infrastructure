# vti-specs-core

Generated Trust Task wire types for every Trust Task family VTI speaks other than `rooms/*`, `vta/*` and `vtc/*`, at exactly the specification
versions this crate's `trust-tasks.lock` pins.

`build.rs` runs [`trust-tasks-build`](https://crates.io/crates/trust-tasks-build)
over the lock and the bundles vendored under `trust-tasks/` (each checked
against its pinned digest; the build never uses the network). Each version
lands at the module path the deprecated prebuilt `trust_tasks_rs::specs` gave
it, with a `schema_index` over the locked versions.

Depend on [`vti-specs`](https://crates.io/crates/vti-specs) — or use
`vta_sdk::specs` — rather than on this crate directly: it re-exports every
family and merges the four crates' indexes.

To pin a version: `trust-tasks -C vti-specs-core add <slug>/<M.N>`, then commit
`trust-tasks.toml`, `trust-tasks.lock` and the new bundle.
