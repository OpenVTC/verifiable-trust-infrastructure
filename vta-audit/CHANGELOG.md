# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.3.2...vta-audit-v0.3.3) — 2026-09-06


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.3.1...vta-audit-v0.3.2) — 2026-09-06


### Documentation

- **audit**: Say at the macro that `audit!` never reaches the sink ([#1240](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1240))

The module docs already explain the split — the macro emits a tracing
  event, `record`/`record_with_detail` persist, call both. The macro's own
  doc comment said only "Emit a structured audit event to the tracing
  subsystem", and that is what a reader sees on hover or jump-to-definition
  at a call site.

  The gap matters because the call site carries no other signal. A handler
  with `audit!("session.revoke", …)` three lines above its response reads,
  on every measure a reviewer applies, as a handler that audits: it
  compiles, it is named `audit`, it emits an event — and the row an operator
  goes looking for is not there.

  Not hypothetical. `vta/management/reload-services` shipped with this macro
  and no sink write, so restarting an agent left nothing in the queryable
  trail. It took a runtime census to notice, and the census could not see
  the task at all until it was specified upstream ([#1239](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1239)). Two layers of
  checking passed over a handler that looked audited and was not.

  Docs only; no behaviour change. `cargo test -p vta-audit`, `cargo doc` and
  `cargo fmt --check` clean.



## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.3.0...vta-audit-v0.3.1) — 2026-08-29


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.2.0...vta-audit-v0.3.0) — 2026-08-28


### Added

- **audit**: Bound the operator reason an audit row keeps ([#1132](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1132))

Framework 0.5.0 requires every free-text member to carry a bound. Most of that
  is upstream schema work, but one free-text path is this workspace's own and was
  bounded by nothing: the operator `reason` that `record_with_detail` writes into
  the audit log.

  The cost here is worse than the wire cost 0.5.0 argues from. The row goes into
  a hash-chained, append-only log, so an oversized `detail` is permanent and
  cannot be trimmed later without breaking the chain that makes the log evidence.

  Truncated at 4096 characters rather than rejected, and that choice is the
  substance: this runs after the operation it records has already happened, so
  refusing the row would trade an over-long reason for no audit record at all —
  losing the evidence to protect its formatting. The cut is marked, because a
  silently shortened reason reads as the operator's own words.

  Cut on a character boundary: byte-slicing panics mid-codepoint, and would do so
  on the first operator who wrote a reason in a language this workspace did not
  anticipate.

  The rest of the free-text rule is upstream and already in hand: 1013 of 1067
  registry free-text members carry no maxLength, and dtgwg-trust-tasks-tf#296 is
  open across 275 files to fix exactly that. Taking the latest trust-tasks-rs
  today would not bound free text — 0.14.0 predates it.



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



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.10...vta-audit-v0.2.0) — 2026-08-26


### Added

- **audit**: Make the audit destination a deployment choice, not a protocol one ([#1049](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1049))

`AuditLogEntry` is `{id, timestamp, action, actor, resource, outcome, channel,
  contextId, detail}` — no signature, no hash chain. The log corroborates what
  happened; it cannot prove it, and a compromised VTA can rewrite its own history.
  The canonical `AuditEnvelope` already names the members that would change that
  (`prevHash`, `entryHash`, `schemaVersion`) and records why this maintainer omits
  them: its log is flat and unchained.

  This does not add tamper-evidence, deliberately. It adds the seam, so an
  operator who needs a stronger guarantee implements one — an append-only file, a
  transparency log, a blockchain anchor, a hash chain filling in those three
  members — without the VTA committing to any scheme. Closes #1031.

  ## The shape



## [0.1.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.9...vta-audit-v0.1.10) — 2026-08-22


## [0.1.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.8...vta-audit-v0.1.9) — 2026-08-21


## [0.1.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.7...vta-audit-v0.1.8) — 2026-08-20


## [0.1.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.6...vta-audit-v0.1.7) — 2026-08-18


## [0.1.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.5...vta-audit-v0.1.6) — 2026-08-17


## [0.1.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.4...vta-audit-v0.1.5) — 2026-08-16


## [0.1.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.3...vta-audit-v0.1.4) — 2026-08-16


## [0.1.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-audit-v0.1.2...vta-audit-v0.1.3) — 2026-08-13


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


