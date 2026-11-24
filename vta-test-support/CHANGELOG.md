# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.3.0...vta-test-support-v0.4.0) — 2026-11-24


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.2.0...vta-test-support-v0.3.0) — 2026-11-18


### Added

- **vta**: Every DID the VTA holds through one method-neutral surface (vta/dids/*) ([#2763](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2763))

* feat(vta)!: every DID the VTA holds through one method-neutral surface (vta/dids/*)



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.1.0...vta-test-support-v0.2.0) — 2026-11-15


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-test-support-v0.1.0) — 2026-11-14


### Changed

- **vta**: Decouple vta-cli-common, split key/room modules, extract vta-test-support, share reject helpers and service plumbing ([#2730](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2730))

* refactor(vta): put vta-cli-common and dialoguer behind cli-synthesis ([#2566](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2566))

  Only the `vta` binary's offline CLI modules and setup wizard use them,
  and the binary already requires `cli-synthesis`. The library — and so
  vta-enclave — no longer compiles vtc-client, ratatui, qrcode, dialoguer
  or crossterm: `cargo tree -p vta-enclave -e normal` drops from 981 to
  ~935 unique lines.

  The vti-rooms comment claimed `default-features = false` kept the host
  half out of the build; feature unification through vti-rooms-dtg (which
  verifies through `vti_rooms::authz`) turns `host` back on. Say so,
  and why it costs nothing new.


