# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-hcp-v0.1.0...vti-specs-hcp-v0.1.1) — 2026-11-28


### Added

- **hcp**: Pin the hcp/* 0.1 suite in vti-specs-hcp (A1) ([#2859](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2859))

HCP V0 task A1 (docs/05-design-notes/hcp-tasks.md): pins the seven hcp/*
  0.1 tasks V0 speaks in vti-specs-hcp: hcp/grants/{request,revoke,revoked},
  hcp/entries/{query,create}, hcp/audit/read and hcp/disclosures/summary. The
  bundles are as published at trusttasks.org, digests in the lock, and
  trust-tasks-build 0.3.0 generates every one. vti-specs re-exports the family
  as vti_specs::hcp and merges its index; the six generated tables stay
  disjoint.

  Pinned is not served: nothing dispatches an hcp/* task until A8 wires the
  handlers behind the `hcp` feature. The one census that holds every pinned
  request URI, vti-mcp-common's verb classification, gains `revoked`
  (hcp/grants/revoked, a provider's revocation notice) as mutating, beside
  `granted` and `notice`.

  The suite is `draft`, so a version may change in place upstream:
  `trust-tasks -C vti-specs-hcp check` is what says a re-pin still matches.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-hcp-v0.1.0) — 2026-11-28


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


