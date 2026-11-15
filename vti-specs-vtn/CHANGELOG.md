# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtn-v0.2.2...vti-specs-vtn-v0.2.3) — 2026-11-14


### Build & CI

- **deps**: Enforce cargo-deny bans/sources, drop unused deps, hoist shared deps, forbid unsafe ([#2708](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2708))

* build(deps): enforce cargo-deny bans/sources, drop unused deps, hoist shared deps, forbid unsafe

  pgp, openssl only via webauthn-rs 0.5, no wildcards, and
  multiple-versions = "deny" with a skip list of today's duplicates grouped by
  cause. The two advisory ignores cargo-deny reports as not detected
  (RUSTSEC-2026-0381, RUSTSEC-2024-0436) are removed, the stale [graph]
  comment rewritten, and the yanked crypto-bigint 0.7.6 moved to 0.7.11.

  ring leaves the VTA and VTC graphs; it stays only under attest-verify.

  removed from 19 crates; deliberate ones are listed under
  [package.metadata.cargo-machete] ignored. A tier-0 "manifest hygiene" CI job
  runs cargo-machete and the lint check.

  once in [workspace.dependencies]; vta-tee inherits aws-lc-rs. The five
  crypto crates carry real minimum-patch floors, enforced by
  check-workspace-version-reqs.py.

  (check-workspace-lints.py); unsafe_code = "forbid" workspace-wide, with
  the four crates that need unsafe restating the table at "deny" and
  rewritten safely. The two missing publish = false comments are added.



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

