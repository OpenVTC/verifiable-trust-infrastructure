# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keyspaces-v0.1.5...vta-keyspaces-v0.2.0) — 2026-08-20


### Added

- **vta**: Dedup keyed Trust Tasks on an idempotency key ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011))

A client that retries a timed-out request is doing the right thing. The
  dangerous case is the one where the VTA processed it and only the reply
  was lost, because the retry then produces a second durable effect —
  `webvh/dids/create` being the sharp example, where auto-assigned paths
  mean the retry mints a *different* DID and the first stays published
  with nobody holding a reference to it.

  The existing `trust_tasks::replay` layer cannot catch that. It keys on
  `(actor, envelope-id)` and every SDK path mints a fresh `urn:uuid:` per
  attempt, so a genuine retry sails past it. Its own module docs name this
  work as the deliberate follow-up.

  ## Built on the store that was already here



## [0.1.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keyspaces-v0.1.4...vta-keyspaces-v0.1.5) — 2026-08-18


## [0.1.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keyspaces-v0.1.3...vta-keyspaces-v0.1.4) — 2026-08-17


### Added

- **vta-keys**: Add non-extractable internal signing keys ([#995](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/995))

An ordinary VTA key is BIP-32 derived, so anyone holding the 24-word mnemonic
  can reconstruct it offline. That is what makes the VTA recoverable, and equally
  what makes "the operator cannot obtain this key" false — the second limb of what
  eIDAS calls sole control.

  An internal key is generated from the system CSPRNG, has no derivation path, and
  is never returned by any surface. The VTA acts only as a signing oracle for it.

  Deliberately not a flag on the imported-key path. That path wraps its secrets
  under a KEK derived from the master seed (derive_kek(seed, salt)), so a
  non-extractable flag on it would be decorative: the boundary it claims to
  enforce has already been walked around. Internal keys get their own keyspace,
  INTERNAL_KEYS, with no seed involvement at any point, and that keyspace is in
  EXCLUDED_FROM_BACKUP by design — a backup carrying it would be an export of keys
  the VTA promises never to export, and restoring it elsewhere would clone a
  signer.

  Refused for did:webvh log entries, enforced in code rather than left to
  guidance. WebVH is append-only and each entry is authorised by the update key
  the previous entry named; an unrecoverable update key means that if storage is
  lost the DID can never be updated again by anyone, permanently, and every
  integration pinned to it is stranded. Credentials can be re-issued, an
  append-only identity log cannot. Internal keys remain fine as a signing
  verificationMethod inside a published document, where loss costs the ability to
  produce new signatures rather than control of the identity.

  The export refusal is not a permission check — admin is not a bypass, because
  the value of the origin is that no caller holds this power. There are two
  refusals (an early return and an in-match arm); removing either leaves the other,
  and removing both does not compile, since the match over KeyOrigin becomes
  non-exhaustive. An export path cannot silently reopen.

  Operator surfaces carry the cost prominently: `pnm keys create --internal`
  prints what is lost and requires the operator to type a confirmation phrase
  rather than mash y, the response repeats the warning, and docs/02-vta/
  internal-keys.md covers when to use one, what actually protects it (enclave
  measurement + KMS, not a mnemonic), and the two things that genuinely destroy
  it.



## [0.1.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keyspaces-v0.1.2...vta-keyspaces-v0.1.3) — 2026-08-16


## [0.1.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keyspaces-v0.1.1...vta-keyspaces-v0.1.2) — 2026-08-13


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


