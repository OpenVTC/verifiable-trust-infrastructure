# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.7.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.7.0...vta-test-support-v0.7.1) — 2026-11-28


### Added

- **vta**: Self-register the VTA's DID with a DID hosting service and keep the account alive ([#2848](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2848))

* feat(vta): self-register the VTA's DID with a third-party DID hosting service

  Pins did-management/account/{register,renew,status,expiry-notice}/0.1 and
  server/info/0.2 (vti-specs-core) and adds the VTA side of guest
  self-registration:

  - WebvhHostClient: server_info (and an anonymous, unsigned form for a VTA
    with no identity yet), register_account (invite admission + optional
    referral, over HTTPS only), renew_account, account_status, and
    for_server_offline. The account tasks' refusal codes map to statuses an
    operator can act on. The invite halves never reach a Debug string.
  - Outbound::rest_only: a reply to an issuer whose DID does not resolve yet
    can only come back as the HTTPS response.
  - register_did_with_server takes an optional admission: with one it sends
    account/register instead of did/register, keeping the record flip,
    concurrency check and audit.
  - Setup: create_webvh gains an optional [vta_did.hosting] block. Before
    minting, setup checks the host's server/info (the domain admits invites,
    the path is under one of its prefixes, matched on whole segments); after
    minting it registers the DID, so a bad invite fails setup immediately.
  - The stub webvh host serves server/info/0.2 and account/register, renew
    and status, schema-checked; a round-trip test drives the real client.



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.6.0...vta-test-support-v0.7.0) — 2026-11-24


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.5.0...vta-test-support-v0.6.0) — 2026-11-24


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-test-support-v0.4.0...vta-test-support-v0.5.0) — 2026-11-24


### Build & CI

- **deps**: Affinidi-tdk 0.50 and affinidi-messaging-sdk 0.51 (trust-tasks-rs 0.41 across the SDK boundary) ([#2797](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2797))

* build(deps)!: affinidi-tdk 0.50 and affinidi-messaging-sdk 0.51 (trust-tasks-rs 0.41 across the SDK boundary)

  affinidi-messaging-sdk 0.51 and affinidi-tdk 0.50 move the messaging SDK onto
  trust-tasks-rs / trust-tasks-proof 0.41 (affinidi-tdk-rs #1189), the
  workspace's copy. Its generated Trust Task types are in the public API of
  vta-sdk and the crates that re-export it, so a consumer moves with it.

  - vta-sdk's TSP account/update document is built with
    `TrustTask::for_payload` again: the SDK's generated payload now implements
    the workspace's trust-tasks-rs `Payload` trait, so the named type URI the
    0.49 generation needed ([#2796](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2796)) is gone.
  - deny.toml: the mediator crates 0.55 (test-mediator, mediator-admin,
    mediator-tui) are now the only previous-generation crates in the graph.
    affinidi-tdk 0.49, affinidi-messaging-sdk 0.50, trust-tasks-rs and
    trust-tasks-proof 0.40 and jsonwebtoken 11 are listed only through them,
    and all drop together with mediator 0.56.



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


