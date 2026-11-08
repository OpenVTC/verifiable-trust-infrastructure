# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtn-v0.2.1...vti-specs-vtn-v0.2.2) — 2026-11-05


### Added

- **vti-specs-vtn**: Pin vtn/registry/check 0.1 and vtn/registry/status 0.1 ([#2468](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2468))

`vtn/registry/check` lets anyone ask a network to ask its trust registry whether
  a party is published as its member, returning the registry's own signed answer
  verbatim, for a registry that serves no HTTPS. `vtn/registry/status` lets an
  administrator read the writer, whether it is connected, the last reconcile, and
  every record against the projection (ok, missing, stale, wrong). Specified in
  trustoverip/dtgwg-trust-tasks-tf#1050.



## [0.2.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtn-v0.2.0...vti-specs-vtn-v0.2.1) — 2026-11-04


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtn-v0.1.0...vti-specs-vtn-v0.2.0) — 2026-11-04

