# vti-specs-hcp

Generated Trust Task wire types for `hcp/*`, the Human Context Protocol, at
exactly the specification versions this crate's `trust-tasks.lock` pins. Nothing
is pinned yet; the `hcp/*` 0.1 tasks the VTA's HCP Provider uses are added in a
later change.

`build.rs` runs [`trust-tasks-build`](https://crates.io/crates/trust-tasks-build)
over the lock and the bundles vendored under `trust-tasks/` (each checked
against its pinned digest; the build never uses the network). Each version
lands at the module path the deprecated prebuilt `trust_tasks_rs::specs` gave
it, with a `schema_index` over the locked versions.

To pin a version: `trust-tasks -C vti-specs-hcp add <slug>/<M.N>`, then commit
`trust-tasks.toml`, `trust-tasks.lock` and the new bundle.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
