# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.10.0...vta-external-v0.11.0) — 2026-10-28


### Added

- **external**: Serve and send only the current external/* versions ([#2311](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2311))

trust-tasks-rs 0.35 deprecates every superseded Trust Task version and withdraws each about 90 days later. Every current `external/*` version is already in 0.35, so the VTA serves it now and stops serving the old one, and every client in the workspace sends it.

  Served now (the old versions are refused `unsupportedVersion`/`unsupportedType`):

  - `external/accounts/{list,get,create,update,bindings/grant,bindings/revoke,probe,keys/rotate,suspend,resume,archive,restore}` 0.2 (from 0.1). `secret/set`, `setup` and `delete` stay at 0.1, their current version.
  - `external/credentials/issue` 0.3 only (0.1 and 0.2 are no longer served).

  On the wire:

  - An account's `lastProbe` (`AccountProbeReport`, `external/_shared/0.2`) names when the probe ran `probedAt`, not `at`. A report stored by an earlier VTA is answered under the new name; nothing is rewritten.
  - Issuance is 0.3's: a `scope` for every brokered model but `s3-static-presign`, which takes a `presign` batch of at most 64 operations (a 65th is `malformedRequest`); a batch whose sealed answer would not fit is `responseTooLarge` and costs none of the binding's rate. 0.1's single, unbound presigned request is gone with it.

  Clients move with it:

  - `vta-sdk`: `TASK_EXTERNAL_ACCOUNTS_*_0_1` become `_0_2`; `TASK_EXTERNAL_CREDENTIALS_ISSUE_0_1`/`_0_2` are removed. `VtaClient::external_credentials_issue` sends 0.3 (it took the 0.1 payload); `external_credentials_issue_v2`/`_v3` are removed, and `external_credentials_issue_presign` no longer falls back to 0.2.
  - `vta-external`: `batch::PresignBatch`/`PresignRequest` are 0.3's types and `MAX_OPERATIONS` is 64; `MAX_OPERATIONS_0_3` is removed.
  - `pnm external issue` drops `--object-key` (0.3's `scope` takes none; an `s3-static-presign` account is asked with `--presign`).
  - The VTC (`auth: vta-account` storage) asks its VTA only at 0.3: the account check is a one-`get` batch on the canary, reads and deletes are batches of one, and a write the VTC makes itself is presigned as a `put` bound to its length and SHA-256 (`PresignedBlobs::put` hashes the staged file whenever its presigner `presigns_ops`). It no longer falls back to 0.2 for a VTA without 0.3.



### Build & CI

- **deps**: Compile only the trust-tasks-rs spec families each crate uses ([#2326](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2326))

The workspace `trust-tasks-rs` entry enabled `all-specs`, so every crate that
  depends on it, and every consumer of a published VTI crate, compiled all 34
  generated spec families (~70 MB of Rust, 14 GB peak rustc RSS). The workspace
  entry now enables `validate` only, and each crate lists the families it names:
  a `trust_tasks_rs::specs::<family>` path, or a Type URI it sends, serves or
  looks up in `schema_index`.

  The workspace union is 29 families. The five dropped (chat, process-attestation,
  sync, vrc, webvh) appear nowhere in VTI: no path, no Type URI, no handler. A
  received document of one of those types was already refused as unsupported;
  it is now dispatched to that refusal without a schema check first.

  What shrinks: `vti-rooms-wasm` compiles `rooms` alone (trust-tasks-rs dev
  build 14.2 GB / 174 s -> 1.5 GB / 7 s). Everything that depends on vta-sdk
  still needs 23-29 families, so the workspace, service and mobile builds are
  roughly unchanged (mobile `check` 12.9 -> 11.1 GB); the swap safety nets stay.



### Chore

- **deps**: Trust-tasks-rs 0.36, affinidi-tdk 0.36, affinidi-messaging-sdk 0.44, mediator 0.48 ([#2319](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2319))

One trust-tasks-rs in the graph again, at 0.36.1 — the first release
  carrying vta/contexts/delete/1.1 (trust-tasks-tf #967). TDK moved in
  lockstep (affinidi-tdk-rs #978: affinidi-tdk 0.36, affinidi-messaging-sdk
  0.44) and so did the mediator (affinidi-messaging-mediator #46, released as
  0.48.0: test-mediator, mediator-admin, mediator-tui).

  trust-tasks-rs 0.36 emits trust-task-error/0.6, which adds the
  unsupportedExtension and indeterminate standard codes (framework 0.7,
  SPEC §8.3). Both services' framework_error_type_uri() move to 0.6 so an
  unrouted refusal speaks the same version as a routed one — the drift
  unrouted_and_routed_errors_agree_on_the_type_uri exists to catch — and the
  fixtures standing in for this workspace's own refusals follow, keeping
  one error version in vtc-service's binding census. Fixtures for foreign
  peers (a DID host) keep 0.5: a consumer still accepts it (SPEC §5.2).
  vta-sdk and the admin console recognise any trust-task-error/ version.

  0.36 also marks every prebuilt spec module deprecated in favour of
  trust-tasks-build. The workspace already allows `deprecated`;
  vta-external, vti-vetting-pcs and vta-persona did not inherit the
  workspace lints, and now do.



## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.9.0...vta-external-v0.10.0) — 2026-10-27


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


