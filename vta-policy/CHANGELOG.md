# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.12...vta-policy-v0.3.0) — 2026-08-28


### Added

- **vta**: Mint the consent ceremony's correlator instead of deriving it ([#1133](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1133))

* feat(vta): mint the consent ceremony's correlator instead of deriving it

  Framework 0.5.0, *Identifier correlation and linkability*: `id`, `threadId` and
  `ceremony.enactment` MUST be freshly minted and unguessable, and MUST NOT be
  derived from subject data.

  The `task-consent/granted` notice threaded on `wire_digest` — a function of the
  task payload, and the same string the document carries as `payloadDigest`.

  The challenge is 256 bits of randomness, so the digest is not guessable from
  the payload; this is not the "UUIDv5 over a subject identifier" case. The
  mediator is the exposure. `threadId` is routing metadata, and the mediator also
  forwards documents carrying `payloadDigest`; with the same value in both it can
  tie the routing it performs to the digest it carries and link the refusal, the
  approval pushes and the notice into one ceremony with named counterparties.

  `PendingTaskConsent` gains a minted `correlator`, created alongside the
  challenge. The notice threads on it and the body still carries `payloadDigest`
  unchanged, so a requester matching on the digest is unaffected. The requester
  is told the correlator in the `auth:consent_required` refusal beside the digest
  it already receives.

  Smaller than it first looked: the request push to approvers already threaded on
  the request document's own id, so only the requester-facing notice was derived.
  The notice is produced but never consumed in this workspace and is explicitly
  non-load-bearing — the grant check at re-submit is the real gate.



### Chore

- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.2.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.11...vta-policy-v0.2.12) — 2026-08-26


## [0.2.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.10...vta-policy-v0.2.11) — 2026-08-22


## [0.2.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.9...vta-policy-v0.2.10) — 2026-08-21


## [0.2.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.8...vta-policy-v0.2.9) — 2026-08-20


## [0.2.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.7...vta-policy-v0.2.8) — 2026-08-18


## [0.2.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.6...vta-policy-v0.2.7) — 2026-08-17


## [0.2.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.5...vta-policy-v0.2.6) — 2026-08-16


## [0.2.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.4...vta-policy-v0.2.5) — 2026-08-16


## [0.2.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.3...vta-policy-v0.2.4) — 2026-08-14


## [0.2.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-policy-v0.2.2...vta-policy-v0.2.3) — 2026-08-13


### Added

- **release**: Publish vta-service and its closure again ([#962](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/962))

* feat(release): publish vta-service and its closure again

  #938 unpublished `vta-service` and the twelve subsystem crates behind it,
  on the finding that nothing external depended on them. The audit read
  normal dependencies. `openvtc-core` depends on `vta-service` as a
  **dev-dependency**, for `test_support::MockVta` — an in-process VTA its
  end-to-end tests run against. That harness boots the real service, so no
  client crate can stand in for it.

  Unpublishing did not merely freeze the crate. It broke it.

  `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
  ContextDirection}` as its own public API, so **a re-export makes the
  re-exported crate's version part of your public API**: any graph
  combining `vti-common` with another `vta-sdk` consumer must resolve one
  `vta-sdk`. The frozen `vta-service` 0.14.37 asks for `vta-sdk ^0.21`
  while `vti-common` has moved to `^0.23`. A downstream `cargo update`
  resolves both and `vta-service` fails to compile with

    expected `vti_common::acl::ApproveScope`,
       found `vta_sdk::acl::ApproveScope`

  at ten call sites — which is how this surfaced, in openvtc #213. Nothing
  downstream can fix that; only a release that moves the requirements
  together can.

  So the thirteen manifests go back to the workspace default. The cost is
  the closure — twelve subsystem crates return to crates.io, which is
  exactly what #938 set out to stop. Taken deliberately over the
  alternatives: yanking the published copies breaks OpenVTC's tests with no
  replacement, and leaving them up ships a crate on the registry that
  cannot be built.

  **On release ordering.** `cargo publish --dry-run -p vta-service` fails
  today, and will until the closure is on the registry: packaging strips
  path deps, so `vta-keys = "0.2"` resolves the *published* 0.2.1, which
  still asks for `vta-sdk ^0.21` — two nodes, same error. That resolves
  itself in the release, which publishes in dependency order: every
  subsystem crate in this workspace already requires `vta-sdk = "0.23"`, so
  once they upload, `vta-service` verifies against them. Crates whose
  dependencies are all published already dry-run clean (verified on
  `vta-keyspaces` and `vta-config`).

  Docs updated to match: CLAUDE.md, RELEASING.md and the release-plz.toml
  header all said 7-of-21. They now say 20-of-26, name the six that stay
  internal, and record the rule the audit missed — check dev-dependencies,
  in sibling repos, before unpublishing anything.



### Build & CI

- **release**: Adopt release-plz, publish 7 crates instead of 21 ([#938](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/938))

Merging and releasing were the same act. publish.yml fired on every push to
  main and shipped whatever versions were newly present, and a CI guard required
  the version bump to live in the feature PR — so every PR was a release
  decision, taken by whoever opened it, days before it merged. Two open PRs
  touching one crate wrote the same number into the same line of the same
  Cargo.toml, and the second to merge had to rebase, renumber, and fix a
  changelog entry that had gone stale. #932/#936/#937 hit it three times in one
  afternoon.


