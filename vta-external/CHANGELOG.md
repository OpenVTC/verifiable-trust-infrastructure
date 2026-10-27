# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.9.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.9.0...vta-external-v0.9.1) — 2026-10-27


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.8.0...vta-external-v0.9.0) — 2026-10-26


### Added

- Growth types in published crates are #[non_exhaustive] ([#2196](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2196))

A new variant on a public enum, or a new field on a public struct a consumer
  can build with a literal, is a breaking change in a published crate. It kept
  happening on types that were always going to grow (#1231, #1234, #1244, #1247,
  #1250); #1262 fixed it for Capability and AuditEvent only.

  This marks the rest once. 143 enums are marked: every error and refusal enum
  (VtaError, AppError, ...) and the growth vocabularies (kinds, statuses,
  reasons, codes, transports, SealedPayloadV1). 32 structs are marked: config
  and response bags that no caller builds with a literal. Adding the attribute
  is itself breaking, once. After it, additions to these types are minor
  changes.

  Left exhaustive on purpose, and pinned that way by the census:
  VerifiedAssertion, AssertionProof, ActScope, ApproveScope, ContextDirection,
  SigningDomain, TokenStatus and Role. For each of these, every arm must be
  considered, and a downstream wildcard would be the bug.

  Every downstream match in the workspace gets a `_ =>` arm that takes the most
  restrictive or most generic reading: an internal error, a hidden or refused
  entry, a stale attribute. None is unreachable!().

  vta-sdk/tests/non_exhaustive_census.rs fails on a public enum in a published
  library crate whose name ends in Error, Refusal, Violation, Kind, Event,
  Status, Capability, Reason or Code and that is not #[non_exhaustive], unless
  it is listed as deliberately exhaustive with a reason. It also fails when a
  listed enum gains the attribute or disappears.



## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.7.0...vta-external-v0.8.0) — 2026-10-18


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.6.0...vta-external-v0.7.0) — 2026-10-18


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.5.0...vta-external-v0.6.0) — 2026-10-16


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.4.0...vta-external-v0.5.0) — 2026-10-15


### Added

- **vta**: External/credentials/issue 0.3 — responseTooLarge, sized before the rate, and the VTC splits ([#2127](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2127))

* build(deps): trust-tasks-rs 0.31.8 — external/credentials/issue 0.3 (trust-tasks-tf #781)

- **rooms**: Direct uploads — rooms/blobs 0.2 straight to storage, presigned by the VTA (trust-tasks-tf #775) ([#2121](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2121))

* build(deps): trust-tasks-rs 0.31.5 floor — external/credentials/issue 0.2 (trust-tasks-tf #775)

- **rooms**: Rooms/blobs 0.2 — the single-use upload key, and reads straight from storage (trust-tasks-tf #771) ([#2108](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2108))

* build(deps): trust-tasks-rs 0.31.4 floor — rooms/blobs 0.2 and rooms/keys/act (trust-tasks-tf #771)



### Fixed

- **vta-external**: Probe honours VTA_ALLOW_PRIVATE_ENDPOINTS, lifecycle rule per bound prefix ([#2124](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2124))

* fix(vta-external): probe honours VTA_ALLOW_PRIVATE_ENDPOINTS; lifecycle rule per bound prefix



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.3.0...vta-external-v0.4.0) — 2026-10-13


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.2.0...vta-external-v0.3.0) — 2026-10-12


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.1.0...vta-external-v0.2.0) — 2026-10-11


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-external-v0.1.0) — 2026-10-11


### Added

- **vta**: External accounts — short-lived provider credentials with no inbound surface ([#2016](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2016))

* feat(vta): external-accounts capabilities and keyspaces

  Adds the two capabilities the external/* family (trust-tasks-tf #740) gates on: external-accounts-manage, derived by admin alone, and external-auth-use, derived by every role that holds sign (the account's binding, not the role, bounds a consumer). Both are non-additive members of the non-exhaustive Capability enum.

  Registers two keyspaces: external_accounts (settings, bindings, state) in BACKED_UP, and external_secrets (wrapped provider secrets) in EXCLUDED_FROM_BACKUP, so a portable password-protected backup is never a way to take a provider secret away. DID deletion: an account's binding names its consumer, so external_accounts blocks; external_secrets is unrelated.

  The device-binding Capability registry (device/_shared 0.2) does not list the two yet, so device listings carry them under ext until it does.


