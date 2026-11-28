# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-hcp-v0.1.0) — 2026-11-28


### Added

- **hcp**: Skeleton vti-specs-hcp and vta-hcp crates behind the hcp feature (X0b) ([#2852](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2852))

HCP V0 task X0b (docs/05-design-notes/hcp-tasks.md):

  - vti-specs-hcp 0.1.0: the generated hcp/* wire-type crate on the
    vti-specs-vtn pattern (trust-tasks-build 0.2.2, empty trust-tasks.toml and
    lock); the hcp/* 0.1 pins and the vti-specs re-export are A1.
  - vta-hcp 0.1.0: an empty subsystem crate with no dependencies, never on
    vta-service.
  - vta-service feature `hcp` = ["dep:vta-hcp"], off by default; cargo-machete
    ignore until A2 uses it.
  - vta-keyspaces: the hcp.md §10 names (HCP_GRANTS … HCP_NOTICES) and an HCP
    slice, declared but not yet in ALL; each joins ALL with its backup,
    DID-deletion and context-deletion decisions when first written.
  - Workspace and default members, Dockerfile.nitro COPY lines, CLAUDE.md crate
    map and table, publish counts (42 of 53), semver-report.sh exclusion of
    vta-hcp, a feature-flags.md row and a `vta-service hcp` clippy step in
    Feature combos (vta-service builds).


